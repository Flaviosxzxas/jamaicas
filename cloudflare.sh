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
wait # adiciona essa linha para esperar que o comando seja concluído

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

echo "  -- Cadastrando A"
response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data "{\"type\": \"A\", \"name\": \"$DKIMSelector\", \"content\": \"$ServerIP\", \"ttl\": 120, \"proxied\": false}")

echo "Response (A): $response"

echo "  -- Cadastrando SPF"
response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data "{\"type\": \"TXT\", \"name\": \"$ServerName\", \"content\": \\\"v=spf1 a:$ServerName ~all\\\", \"ttl\": 120, \"proxied\": false}")

echo "Response (SPF): $response"

echo "  -- Cadastrando DMARK"
response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data "{\"type\": \"TXT\", \"name\": \"_dmarc.$ServerName\", \"content\": \\\"v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmark@$ServerName; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r\\\", \"ttl\": 120, \"proxied\": false}")

echo "Response (DMARC): $response"

echo "  -- Cadastrando DKIM"
EscapedDKIMCode=$(printf '%s' "$DKIMCode" | sed 's/\"/\\\\\"/g')
response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data "{\"type\": \"TXT\", \"name\": \"mail._domainkey.$ServerName\", \"content\": \\\"v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode\\\", \"ttl\": 120, \"proxied\": false}")

echo "Response (DKIM): $response"

echo "  -- Cadastrando MX"
response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data "{\"type\": \"MX\", \"name\": \"$ServerName\", \"content\": \"$ServerName\", \"ttl\": 120, \"priority\": 10, \"proxied\": false}")

echo "Response (MX): $response"

echo "==================================================== CLOUDFLARE ===================================================="

