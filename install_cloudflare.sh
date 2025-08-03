#!/bin/bash

DOMAIN="$1"
SERVER_IP="$2"
CLOUDFLARE_API_KEY="$3"
CLOUDFLARE_EMAIL="$4"
DKIM_PUBLIC_KEY="$5"

if [ -z "$DOMAIN" ] || [ -z "$SERVER_IP" ] || [ -z "$CLOUDFLARE_API_KEY" ] || [ -z "$CLOUDFLARE_EMAIL" ]; then
    echo "Uso: $0 <DOMINIO> <IP> <CF_API_KEY> <CF_EMAIL> [DKIM_PUBLIC_KEY]"
    exit 1
fi

# Busca DKIM automaticamente dentro do container se não passar manual
if [ -z "$DKIM_PUBLIC_KEY" ]; then
    # Tenta encontrar o nome do container rspamd
    RSPAMD_CONTAINER=$(docker ps --format '{{.Names}}' | grep rspamd | head -n1)
    if [ -n "$RSPAMD_CONTAINER" ]; then
        DKIM_PUBLIC_KEY=$(docker exec "$RSPAMD_CONTAINER" sh -c "[ -f /var/lib/rspamd/dkim/$DOMAIN/default.pub ] && cat /var/lib/rspamd/dkim/$DOMAIN/default.pub" 2>/dev/null | awk -F'"' '{print $2 $4}' | tr -d '[:space:]')
        if [ -n "$DKIM_PUBLIC_KEY" ]; then
            echo "DKIM lido do container $RSPAMD_CONTAINER para $DOMAIN"
        else
            echo "ATENÇÃO: DKIM não encontrado no container $RSPAMD_CONTAINER para $DOMAIN (continuando sem DKIM)..."
        fi
    else
        echo "ATENÇÃO: Container rspamd não encontrado, continuando sem DKIM..."
    fi
fi

if ! command -v jq &> /dev/null; then
    apt-get update && apt-get install -y jq
fi
if ! command -v curl &> /dev/null; then
    apt-get update && apt-get install -y curl
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
        echo "Erro ao obter Zone ID Cloudflare para $DOMAIN"
        return 1
    fi

    local record_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=$type&name=$name" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
        -H "Content-Type: application/json" | jq -r '.result[0].id')

    if [ -z "$record_id" ] || [ "$record_id" = "null" ]; then
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$type\",\"name\":\"$name\",\"content\":\"$content\"$extra}"
    else
        curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$type\",\"name\":\"$name\",\"content\":\"$content\"$extra}"
    fi
}

cloudflare_dns_update "A" "mail.$DOMAIN" "$SERVER_IP" ', "ttl":120, "proxied":false'
cloudflare_dns_update "A" "$DOMAIN" "$SERVER_IP" ', "ttl":120, "proxied":false'
cloudflare_dns_update "MX" "$DOMAIN" "mail.$DOMAIN" ', "ttl":120, "priority":10'
cloudflare_dns_update "TXT" "$DOMAIN" "v=spf1 +a +mx +ip4:$SERVER_IP -all" ', "ttl":120'
cloudflare_dns_update "TXT" "_dmarc.$DOMAIN" "v=DMARC1; p=quarantine; rua=mailto:admin@$DOMAIN" ', "ttl":120'
if [ -n "$DKIM_PUBLIC_KEY" ]; then
    cloudflare_dns_update "TXT" "default._domainkey.$DOMAIN" "$DKIM_PUBLIC_KEY" ', "ttl":120'
fi

echo "Registros DNS do Cloudflare criados/atualizados para $DOMAIN!"
