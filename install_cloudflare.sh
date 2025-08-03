#!/bin/bash

# USO: ./script.sh dominio.com IP CLOUDFLARE_API_KEY CLOUDFLARE_EMAIL

DOMAIN="$1"
SERVER_IP="$2"
CLOUDFLARE_API_KEY="$3"
CLOUDFLARE_EMAIL="$4"
OK=1

if [ -z "$DOMAIN" ] || [ -z "$SERVER_IP" ] || [ -z "$CLOUDFLARE_API_KEY" ] || [ -z "$CLOUDFLARE_EMAIL" ]; then
    echo "ERRO: Uso: $0 <DOMINIO> <IP> <CF_API_KEY> <CF_EMAIL>"
    exit 1
fi

# ------ CONFIG DO SELETOR ------
DKIM_SELECTOR="default"    # ou 'mail' dependendo do seu setup
DKIM_FILE="/etc/opendkim/keys/$DOMAIN/mail.txt"   # Ajuste para seu arquivo real

if [ ! -f "$DKIM_FILE" ]; then
    echo "ERRO: Arquivo de DKIM não encontrado: $DKIM_FILE"
    exit 1
fi

# ----- EXTRAI SÓ A CHAVE PÚBLICA (SEM PREFIXO) -----
PUBKEY=$(grep '^p=' "$DKIM_FILE" | sed 's/^p=//;s/[ \t\r\n]*//g')

if [ -z "$PUBKEY" ]; then
    echo "ERRO: Não foi possível extrair o valor da chave pública (p=) do arquivo DKIM."
    exit 1
fi

# ----- MONTA O VALOR FINAL DO TXT -----
DKIM_TXT_VALUE="v=DKIM1; k=rsa; p=$PUBKEY"

# --- Instala dependências se necessário ---
if ! command -v jq &> /dev/null; then
    apt-get update -y >/dev/null 2>&1 && apt-get install -y jq >/dev/null 2>&1
fi
if ! command -v curl &> /dev/null; then
    apt-get update -y >/dev/null 2>&1 && apt-get install -y curl >/dev/null 2>&1
fi

# ------ Função para atualizar Cloudflare ------
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

    local data
    if [ "$type" = "TXT" ]; then
        # Envia o valor sem aspas duplas, tudo em uma linha só
        data=$(jq -n --arg type "$type" --arg name "$name" --arg content "$content" --arg ttl "120" '{
            type: $type,
            name: $name,
            content: $content,
            ttl: ($ttl|tonumber)
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

# --- Exemplo de uso ---
cloudflare_dns_update "TXT" "$DKIM_SELECTOR._domainkey.$DOMAIN" "$DKIM_TXT_VALUE" ""

if [ "$OK" -eq 1 ]; then
    echo "DKIM configurado corretamente no Cloudflare!"
else
    echo "ERRO ao configurar DKIM."
fi
