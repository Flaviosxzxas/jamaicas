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

sleep 10

echo "==================================================== CLOUDFLARE ===================================================="

DKIMCode=$(/root/dkimcode.sh)

sleep 5

echo "  -- Obtendo Zona"
CloudflareZoneID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$Domain&status=active" \
  -H "X-Auth-Email: $CloudflareEmail" \
  -H "X-Auth-Key: $CloudflareAPI" \
  -H "Content-Type: application/json" | jq -r '.result[0].id')

if [ -z "$CloudflareZoneID" ]; then
  echo "Erro: Não foi possível obter o ID da zona do Cloudflare." >&2
  exit 1
fi

# Criar registro A
echo "  -- Cadastrando A"
response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data "$(jq -n --arg type "A" --arg name "$DKIMSelector" --arg content "$ServerIP" --argjson ttl 120 --argjson proxied false \
        '{type: $type, name: $name, content: $content, ttl: $ttl, proxied: $proxied}')")
echo "Response (A): $response" >> /root/cloudflare_logs.txt

# Criar registro SPF
echo "  -- Cadastrando SPF"
response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data "$(jq -n --arg type "TXT" --arg name "$ServerName" --arg content "v=spf1 a:$ServerName ~all" --argjson ttl 120 --argjson proxied false \
        '{type: $type, name: $name, content: $content, ttl: $ttl, proxied: $proxied}')")
echo "Response (SPF): $response" >> /root/cloudflare_logs.txt

# Criar registro DMARC
echo "  -- Cadastrando DMARC"
response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data "$(jq -n --arg type "TXT" --arg name "_dmarc.$ServerName" --arg content "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmark@$ServerName; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r" --argjson ttl 120 --argjson proxied false \
        '{type: $type, name: $name, content: $content, ttl: $ttl, proxied: $proxied}')")
echo "Response (DMARC): $response" >> /root/cloudflare_logs.txt

# Criar registro DKIM
echo "  -- Cadastrando DKIM"
EscapedDKIMCode=$(printf '%s' "$DKIMCode" | sed 's/\"/\\\\\"/g')
response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data "$(jq -n --arg type "TXT" --arg name "mail._domainkey.$ServerName" --arg content "v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode" --argjson ttl 120 --argjson proxied false \
        '{type: $type, name: $name, content: $content, ttl: $ttl, proxied: $proxied}')")
echo "Response (DKIM): $response" >> /root/cloudflare_logs.txt

# Criar registro MX
echo "  -- Cadastrando MX"
response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data "$(jq -n --arg type "MX" --arg name "$ServerName" --arg content "$ServerName" --argjson ttl 120 --argjson priority 10 --argjson proxied false \
        '{type: $type, name: $name, content: $content, ttl: $ttl, priority: $priority, proxied: $proxied}')")
echo "Response (MX): $response" >> /root/cloudflare_logs.txt

echo "==================================================== CLOUDFLARE ===================================================="
