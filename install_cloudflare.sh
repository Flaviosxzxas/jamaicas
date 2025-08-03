#!/bin/bash

# Parâmetros obrigatórios
DOMAIN="$1"
CLOUDFLARE_API_KEY="$2"
CLOUDFLARE_EMAIL="$3"

if [ -z "$DOMAIN" ] || [ -z "$CLOUDFLARE_API_KEY" ] || [ -z "$CLOUDFLARE_EMAIL" ]; then
    echo "Uso: $0 <DOMINIO> <CF_API_KEY> <CF_EMAIL>"
    exit 1
fi

OK=1

# Busca o container do rspamd
RSPAMD_CONTAINER=$(docker ps --format '{{.Names}}' | grep rspamd | head -n1)
if [ -z "$RSPAMD_CONTAINER" ]; then
    echo "ERRO: Container rspamd não encontrado"
    exit 1
fi

# Pega DKIM puro do arquivo, remove aspas, parênteses, linhas extras, etc.
DKIM_PUBLIC_KEY=$(
    docker exec "$RSPAMD_CONTAINER" sh -c "cat /var/lib/rspamd/dkim/$DOMAIN/default.pub" 2>/dev/null |
    grep -v -E "^[#;']| IN TXT |^\(" |     # Remove linhas BIND/export
    tr -d '";()' |                        # Remove aspas, parênteses, ponto e vírgula
    tr -d '\n' | tr -s ' ' |              # Tudo em uma linha só
    sed -E 's/^[ \t]+|[ \t]+$//g'         # Remove espaços início/fim
)

# Força prefixo se veio só "p="
if [[ "$DKIM_PUBLIC_KEY" =~ ^p= ]]; then
    DKIM_PUBLIC_KEY="v=DKIM1; k=rsa; $DKIM_PUBLIC_KEY"
fi

if [ -z "$DKIM_PUBLIC_KEY" ]; then
    echo "ERRO: DKIM não encontrado ou está vazio para $DOMAIN"
    exit 1
fi

# Instala jq e curl se faltar
if ! command -v jq &> /dev/null; then
    apt-get update -y >/dev/null 2>&1 && apt-get install -y jq >/dev/null 2>&1
fi
if ! command -v curl &> /dev/null; then
    apt-get update -y >/dev/null 2>&1 && apt-get install -y curl >/dev/null 2>&1
fi

# Descobre a ZoneID do Cloudflare
ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN&status=active" \
  -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
  -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
  -H "Content-Type: application/json" | jq -r '.result[0].id')

if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" = "null" ]; then
    echo "ERRO: Não encontrou Zone ID Cloudflare para $DOMAIN"
    exit 1
fi

# Monta o JSON seguro para o TXT DKIM
data=$(jq -n --arg type "TXT" --arg name "default._domainkey.$DOMAIN" --arg content "$DKIM_PUBLIC_KEY" --arg ttl "120" '{
    type: $type,
    name: $name,
    content: $content,
    ttl: ($ttl|tonumber)
}')

# Busca se já existe o registro
RECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=TXT&name=default._domainkey.$DOMAIN" \
    -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
    -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
    -H "Content-Type: application/json" | jq -r '.result[0].id')

if [ -z "$RECORD_ID" ] || [ "$RECORD_ID" = "null" ]; then
    # Cria novo
    resp=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
        -H "Content-Type: application/json" \
        --data "$data")
else
    # Atualiza
    resp=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
        -H "Content-Type: application/json" \
        --data "$data")
fi

success=$(echo "$resp" | jq -r '.success')
if [ "$success" != "true" ]; then
    echo "ERRO: Falha ao criar/atualizar TXT DKIM."
    echo "RESPOSTA DO CLOUDFLARE:"
    echo "$resp"
    exit 1
else
    echo "DKIM adicionado/atualizado com sucesso para $DOMAIN!"
    exit 0
fi
