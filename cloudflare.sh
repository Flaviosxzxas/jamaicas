#!/bin/bash

# Verifique se o script está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi

# Atualizar a lista de pacotes e atualizar pacotes
echo "Atualizando a lista de pacotes..."
sudo apt-get update
sudo apt-get upgrade -y

ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

Domain=$(echo $ServerName | cut -d "." -f2-)
DKIMSelector=$(echo $ServerName | awk -F[.:] '{print $1}')
ServerIP=$(wget -qO- http://ip-api.com/line\?fields=query)

echo "Configurando Servidor: $ServerName"
echo "Domain: $Domain"
echo "DKIMSelector: $DKIMSelector"
echo "ServerIP: $ServerIP"

sleep 5

echo "==================================================== CLOUDFLARE ===================================================="

DKIMCode=$(/root/dkimcode.sh)

# Obter o ID da zona do Cloudflare
echo "  -- Obtendo Zona"
CloudflareZoneID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$Domain&status=active" \
  -H "X-Auth-Email: $CloudflareEmail" \
  -H "X-Auth-Key: $CloudflareAPI" \
  -H "Content-Type: application/json" | jq -r '.result[0].id')

if [ -z "$CloudflareZoneID" ]; then
  echo "Erro: Não foi possível obter o ID da zona do Cloudflare." >&2
  exit 1
fi

# Função para verificar a existência de um registro
get_record_details() {
  local record_name=$1
  local record_type=$2
  curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records?name=$record_name&type=$record_type" \
    -H "X-Auth-Email: $CloudflareEmail" \
    -H "X-Auth-Key: $CloudflareAPI" \
    -H "Content-Type: application/json"
}

record_exists() {
  local record_name=$1
  local record_type=$2
  get_record_details "$record_name" "$record_type" | jq -r '.result | length'
}

create_or_update_record() {
  local record_name=$1
  local record_type=$2
  local record_content=$3
  local record_ttl=120
  local record_priority=$4
  local record_proxied=false

  response=$(get_record_details "$record_name" "$record_type")
  existing_content=$(echo "$response" | jq -r '.result[0].content')
  existing_ttl=$(echo "$response" | jq -r '.result[0].ttl')
  existing_priority=$(echo "$response" | jq -r '.result[0].priority')

  if [ "$record_type" == "MX" ] && [ "$existing_content" == "$record_content" ] && [ "$existing_ttl" -eq "$record_ttl" ] && [ "$existing_priority" -eq "$record_priority" ]; then
    echo "Registro $record_type para $record_name já está atualizado. Pulando."
  elif [ "$record_type" != "MX" ] && [ "$existing_content" == "$record_content" ] && [ "$existing_ttl" -eq "$record_ttl" ]; then
    echo "Registro $record_type para $record_name já está atualizado. Pulando."
  else
    echo "  -- Criando ou atualizando registro $record_type para $record_name"
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
         -H "X-Auth-Email: $CloudflareEmail" \
         -H "X-Auth-Key: $CloudflareAPI" \
         -H "Content-Type: application/json" \
         --data "$(jq -n --arg type "$record_type" --arg name "$record_name" --arg content "$record_content" --arg ttl "$record_ttl" --argjson proxied "$record_proxied" --arg priority "$record_priority" \
            '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber), proxied: $proxied, priority: ($priority | tonumber)}')"
  fi
}

# Criar ou atualizar registros
echo "  -- Configurando registros DNS"
create_or_update_record "$DKIMSelector" "A" "$ServerIP" ""
create_or_update_record "$ServerName" "TXT" "\"v=spf1 a:$ServerName ~all\"" ""
create_or_update_record "_dmarc.$ServerName" "TXT" "\"v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc@$ServerName; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r\"" ""
EscapedDKIMCode=$(printf '%s' "$DKIMCode" | sed 's/\"/\\\"/g')
create_or_update_record "mail._domainkey.$ServerName" "TXT" "\"v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode\"" ""
create_or_update_record "$ServerName" "MX" "$ServerName" "10"
