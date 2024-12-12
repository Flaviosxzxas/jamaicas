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
record_exists() {
  local record_name=$1
  local record_type=$2
  curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records?name=$record_name&type=$record_type" \
    -H "X-Auth-Email: $CloudflareEmail" \
    -H "X-Auth-Key: $CloudflareAPI" \
    -H "Content-Type: application/json" | jq -r '.result | length'
}

# Criar registro A
if [ $(record_exists "$DKIMSelector" "A") -eq 0 ]; then
  echo "  -- Cadastrando A"
  response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
       -H "X-Auth-Email: $CloudflareEmail" \
       -H "X-Auth-Key: $CloudflareAPI" \
       -H "Content-Type: application/json" \
       --data "$(jq -n --arg type "A" --arg name "$DKIMSelector" --arg content "$ServerIP" --argjson ttl 120 --argjson proxied false \
          '{type: $type, name: $name, content: $content, ttl: $ttl, proxied: $proxied}')")
  echo "Response (A): $response" >> /root/cloudflare_logs.txt
else
  echo "Registro A já existe. Pulando." >> /root/cloudflare_logs.txt
fi

# Criar registro SPF
if [ $(record_exists "$ServerName" "TXT") -eq 0 ]; then
  echo "  -- Cadastrando SPF"
  response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
       -H "X-Auth-Email: $CloudflareEmail" \
       -H "X-Auth-Key: $CloudflareAPI" \
       -H "Content-Type: application/json" \
       --data "$(jq -n --arg type "TXT" --arg name "$ServerName" --arg content "v=spf1 a:$ServerName ~all" --arg ttl "120" --argjson proxied false \
          '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber), proxied: $proxied}')")
  echo "Response (SPF): $response" >> /root/cloudflare_logs.txt
else
  echo "Registro SPF já existe. Pulando." >> /root/cloudflare_logs.txt
fi

# Criar registro DMARC
if [ $(record_exists "_dmarc.$ServerName" "TXT") -eq 0 ]; then
  echo "  -- Cadastrando DMARC"
  response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
       -H "X-Auth-Email: $CloudflareEmail" \
       -H "X-Auth-Key: $CloudflareAPI" \
       -H "Content-Type: application/json" \
       --data "$(jq -n --arg type "TXT" --arg name "_dmarc.$ServerName" --arg content "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc@$ServerName; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r" --arg ttl "120" --argjson proxied false \
          '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber), proxied: $proxied}')")
  echo "Response (DMARC): $response" >> /root/cloudflare_logs.txt
else
  echo "Registro DMARC já existe. Pulando." >> /root/cloudflare_logs.txt
fi

# Criar registro DKIM
if [ $(record_exists "mail._domainkey.$ServerName" "TXT") -eq 0 ]; then
  echo "  -- Cadastrando DKIM"
  EscapedDKIMCode=$(printf '%s' "$DKIMCode" | sed 's/\"/\\\\\"/g')
  response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
       -H "X-Auth-Email: $CloudflareEmail" \
       -H "X-Auth-Key: $CloudflareAPI" \
       -H "Content-Type: application/json" \
       --data "$(jq -n --arg type "TXT" --arg name "mail._domainkey.$ServerName" --arg content "v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode" --arg ttl "120" --argjson proxied false \
          '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber), proxied: $proxied}')")
  echo "Response (DKIM): $response" >> /root/cloudflare_logs.txt
else
  echo "Registro DKIM já existe. Pulando." >> /root/cloudflare_logs.txt
fi

