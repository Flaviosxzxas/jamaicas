#!/bin/bash

set -Eeuo pipefail
trap 'echo "[ERRO] linha $LINENO: $BASH_COMMAND (status $?)" >&2' ERR

ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

# Verificar argumentos
if [ -z "$ServerName" ] || [ -z "$CloudflareAPI" ] || [ -z "$CloudflareEmail" ]; then
  echo "Erro: Argumentos insuficientes."
  echo "Uso: $0 <ServerName> <CloudflareAPI> <CloudflareEmail>"
  exit 1
fi

# Extrair domínio raiz
KNOWN_DOUBLE_TLDS="com.mx|com.br|co.uk|com.ar|com.au|co.jp|com.co|net.mx|org.mx|gob.mx"
DOTS=$(echo "$ServerName" | tr -cd '.' | wc -c)
if echo "$ServerName" | grep -qE "\.($KNOWN_DOUBLE_TLDS)$"; then
    Domain=$(echo "$ServerName" | awk -F. '{print $(NF-2)"."$(NF-1)"."$NF}')
elif [ "$DOTS" -eq 1 ]; then
    Domain="$ServerName"
else
    Domain=$(echo "$ServerName" | awk -F. '{print $(NF-1)"."$NF}')
fi

MailServerName="mail.$ServerName"

# Obter IP público
ServerIP=$(curl -4 -fsS --max-time 5 https://api.ipify.org)
if [ -z "$ServerIP" ]; then
  echo "Erro: Não foi possível obter o IP público."
  exit 1
fi

echo "ServerName:    $ServerName"
echo "Domain:        $Domain"
echo "MailServerName: $MailServerName"
echo "ServerIP:      $ServerIP"

# Instalar jq se necessário
if ! command -v jq &> /dev/null; then
  apt-get install -y jq
fi

# Ler DKIM gerado pelo Rspamd
DKIMCode=$(/root/dkimcode.sh /var/lib/rspamd/dkim/$ServerName/default.pub)
DKIMCode=$(echo "$DKIMCode" | tr -d '\n' | tr -s ' ')
EscapedDKIMCode=$(printf '%s' "$DKIMCode" | sed 's/\"/\\\"/g')

echo "DKIMCode: $DKIMCode"

# Obter Zone ID
CloudflareZoneID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$Domain&status=active" \
  -H "X-Auth-Email: $CloudflareEmail" \
  -H "X-Auth-Key: $CloudflareAPI" \
  -H "Content-Type: application/json" | jq -r '.result[0].id')

if [ -z "$CloudflareZoneID" ] || [ "$CloudflareZoneID" = "null" ]; then
  echo "Erro: Não foi possível obter o Zone ID do Cloudflare."
  exit 1
fi

echo "CloudflareZoneID: $CloudflareZoneID"

get_record_details() {
  curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records?name=$1&type=$2" \
    -H "X-Auth-Email: $CloudflareEmail" \
    -H "X-Auth-Key: $CloudflareAPI" \
    -H "Content-Type: application/json"
}

create_or_update_record() {
  local record_name=$1 record_type=$2 record_content=$3 record_priority=$4
  local record_proxied=false record_ttl=3600

  case "$record_type" in
    A)   record_ttl=1800 ;;
    MX)  record_ttl=3600 ;;
    TXT) record_ttl=3600 ;;
  esac

  local response existing_id
  response=$(get_record_details "$record_name" "$record_type")
  existing_id=$(echo "$response" | jq -r '.result[0].id')

  local data
  if [ "$record_type" = "MX" ]; then
    data=$(jq -n \
      --arg type "$record_type" --arg name "$record_name" \
      --arg content "$record_content" --arg ttl "$record_ttl" \
      --argjson proxied "$record_proxied" --arg priority "$record_priority" \
      '{type:$type,name:$name,content:$content,ttl:($ttl|tonumber),proxied:$proxied,priority:($priority|tonumber)}')
  else
    data=$(jq -n \
      --arg type "$record_type" --arg name "$record_name" \
      --arg content "$record_content" --arg ttl "$record_ttl" \
      --argjson proxied "$record_proxied" \
      '{type:$type,name:$name,content:$content,ttl:($ttl|tonumber),proxied:$proxied}')
  fi

  if [ "$existing_id" = "null" ] || [ -z "$existing_id" ]; then
    echo "  -- Criando ($record_type) $record_name..."
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
      -H "X-Auth-Email: $CloudflareEmail" -H "X-Auth-Key: $CloudflareAPI" \
      -H "Content-Type: application/json" --data "$data" | jq -r '.success,.errors'
  else
    echo "  -- Atualizando ($record_type) $record_name [ID: $existing_id]..."
    curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records/$existing_id" \
      -H "X-Auth-Email: $CloudflareEmail" -H "X-Auth-Key: $CloudflareAPI" \
      -H "Content-Type: application/json" --data "$data" | jq -r '.success,.errors'
  fi
}

MTASTS_POLICY_ID="$(date +%Y%m%d%H%M)"

create_or_update_record "$ServerName"                    "A"   "$ServerIP"                                                                   ""
create_or_update_record "$MailServerName"                "A"   "$ServerIP"                                                                   ""
create_or_update_record "mta-sts.$ServerName"            "A"   "$ServerIP"                                                                   ""
create_or_update_record "unsubscribe.$ServerName"        "A"   "$ServerIP"                                                                   ""
create_or_update_record "$ServerName"                    "TXT" "\"v=spf1 ip4:$ServerIP -all\""                                               ""
create_or_update_record "_dmarc.$ServerName"             "TXT" "\"v=DMARC1; p=none; sp=none; pct=100; rua=mailto:dmarc-reports@$ServerName; adkim=r; aspf=r; fo=1\"" ""
create_or_update_record "default._domainkey.$ServerName" "TXT" "\"v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode\""                           ""
create_or_update_record "_mta-sts.$ServerName"           "TXT" "\"v=STSv1; id=$MTASTS_POLICY_ID\""                                          ""
create_or_update_record "_smtp._tls.$ServerName"         "TXT" "\"v=TLSRPTv1; rua=mailto:tls-reports@$ServerName\""                         ""
create_or_update_record "$ServerName"                    "MX"  "$MailServerName"                                                             "10"

echo ""
echo "✓ Registros DNS Cloudflare configurados!"
