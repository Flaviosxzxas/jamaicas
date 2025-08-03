#!/bin/bash

DOMAIN="$1"
SERVER_IP="$2"
CLOUDFLARE_API_KEY="$3"
CLOUDFLARE_EMAIL="$4"
DKIM_PUBLIC_KEY="$5"
OK=1

if [ -z "$DOMAIN" ] || [ -z "$SERVER_IP" ] || [ -z "$CLOUDFLARE_API_KEY" ] || [ -z "$CLOUDFLARE_EMAIL" ]; then
    echo "ERRO: Uso: $0 <DOMINIO> <IP> <CF_API_KEY> <CF_EMAIL> [DKIM_PUBLIC_KEY]"
    exit 1
fi

# Busca DKIM automaticamente dentro do container se não passar manual
RSPAMD_CONTAINER=$(docker ps --format '{{.Names}}' | grep rspamd | head -n1)
if [ -z "$DKIM_PUBLIC_KEY" ]; then
    if [ -n "$RSPAMD_CONTAINER" ]; then
        DKIM_PUBLIC_KEY=$(docker exec "$RSPAMD_CONTAINER" sh -c "cat /var/lib/rspamd/dkim/$DOMAIN/default.pub" 2>/dev/null | \
            grep -v -E "^[#;']| IN TXT |^\(" | \
            tr -d '";()' | \
            tr -d '\n' | tr -s ' ' | \
            sed -E 's/^[ \t]+|[ \t]+$//g' )
        # Se veio só "p=", força prefixo
        if [[ "$DKIM_PUBLIC_KEY" =~ ^p= ]]; then
            DKIM_PUBLIC_KEY="v=DKIM1; k=rsa; $DKIM_PUBLIC_KEY"
        fi
    else
        echo "ERRO: Container rspamd não encontrado"
        OK=0
    fi
fi


if ! command -v jq &> /dev/null; then
    apt-get update -y >/dev/null 2>&1 && apt-get install -y jq >/dev/null 2>&1
fi
if ! command -v curl &> /dev/null; then
    apt-get update -y >/dev/null 2>&1 && apt-get install -y curl >/dev/null 2>&1
fi

cloudflare_dns_update() {
    local type="$1"
    local name="$2"
    local content="$3"
    local extra="$4"
    local zone_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN&status=active" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
        -H "Content-Type: application/json" | jq -r '.result[0].id')
    if [ -z "$zone_id" ] || [ "$zone_id" = "null" ]; then
        echo "ERRO: Não encontrou Zone ID Cloudflare para $DOMAIN"
        OK=0
        return 1
    fi

    local result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=$type&name=$name" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
        -H "Content-Type: application/json")
    local record_id=$(echo "$result" | jq -r '.result[0].id')

    # Monta o JSON seguro com jq para o DKIM (ou outros TXT)
    local data
    # Monta o JSON correto para cada tipo
    if [ "$type" = "TXT" ]; then
        data=$(jq -n --arg type "$type" --arg name "$name" --arg content "$content" --arg ttl "120" '{
            type: $type,
            name: $name,
            content: $content,
            ttl: ($ttl|tonumber)
        }')
    elif [ "$type" = "MX" ]; then
        data=$(jq -n --arg type "$type" --arg name "$name" --arg content "$content" --arg priority "10" --arg ttl "120" '{
            type: $type,
            name: $name,
            content: $content,
            priority: ($priority|tonumber),
            ttl: ($ttl|tonumber)
        }')
    elif [ "$type" = "A" ] || [ "$type" = "AAAA" ] || [ "$type" = "CNAME" ]; then
        data=$(jq -n --arg type "$type" --arg name "$name" --arg content "$content" --arg ttl "120" --argjson proxied false '{
            type: $type,
            name: $name,
            content: $content,
            ttl: ($ttl|tonumber),
            proxied: $proxied
        }')
    else
        data=$(jq -n --arg type "$type" --arg name "$name" --arg content "$content" --arg ttl "120" '{
            type: $type,
            name: $name,
            content: $content,
            ttl: ($ttl|tonumber)
        }')
    fi

    local resp
    if [ -z "$record_id" ] || [ "$record_id" = "null" ]; then
        resp=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
            -H "Content-Type: application/json" \
            --data "$data")
    else
        resp=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
            -H "Content-Type: application/json" \
            --data "$data")
    fi

    local success=$(echo "$resp" | jq -r '.success')
    if [ "$success" != "true" ]; then
        echo "ERRO: Falha ao criar/atualizar $type $name."
        echo "RESPOSTA DO CLOUDFLARE:"
        echo "$resp"
        OK=0
    fi
}

cloudflare_dns_update "A" "mail.$DOMAIN" "$SERVER_IP" ""
cloudflare_dns_update "A" "$DOMAIN" "$SERVER_IP" ""
cloudflare_dns_update "MX" "$DOMAIN" "mail.$DOMAIN" ""
cloudflare_dns_update "TXT" "$DOMAIN" "v=spf1 +a +mx +ip4:$SERVER_IP -all" ""
cloudflare_dns_update "TXT" "_dmarc.$DOMAIN" "v=DMARC1; p=quarantine; rua=mailto:admin@$DOMAIN" ""
if [ -n "$DKIM_PUBLIC_KEY" ]; then
    cloudflare_dns_update "TXT" "default._domainkey.$DOMAIN" "$DKIM_PUBLIC_KEY" ""
fi

if [ "$OK" -eq 1 ]; then
    echo "OK"
else
    echo "ERRO"
fi
