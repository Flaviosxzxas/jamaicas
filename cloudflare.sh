#!/bin/bash

# Verifique se o script está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi

# Atualizar pacotes
echo "Atualizando pacotes..."
sudo apt-get update -y && sudo apt-get upgrade -y

# Variáveis principais
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

# Verificar variáveis obrigatórias
if [ -z "$ServerName" ] || [ -z "$CloudflareAPI" ] || [ -z "$CloudflareEmail" ]; then
  echo "Erro: Variáveis obrigatórias ausentes. Certifique-se de informar ServerName, CloudflareAPI e CloudflareEmail."
  exit 1
fi

# Processar a chave DKIM
echo "Extraindo chave DKIM..."
sudo chmod -R 750 /etc/opendkim/
DKIMCode=$(/root/dkimcode.sh)

if [ -z "$DKIMCode" ]; then
  echo "Erro ao extrair a chave DKIM."
  exit 1
fi

# Obter Zone ID do Cloudflare
echo "Obtendo Zone ID do Cloudflare..."
CloudflareZoneID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$Domain&status=active" \
  -H "X-Auth-Email: $CloudflareEmail" \
  -H "X-Auth-Key: $CloudflareAPI" \
  -H "Content-Type: application/json" | jq -r '.result[0].id')

if [ -z "$CloudflareZoneID" ] || [ "$CloudflareZoneID" == "null" ]; then
  echo "Erro: Não foi possível obter o Zone ID do Cloudflare. Verifique o domínio e as credenciais."
  exit 1
fi

echo "Zone ID: $CloudflareZoneID"

# Criar registros DNS
create_record() {
  local type=$1
  local name=$2
  local content=$3
  local ttl=$4
  local priority=$5

  echo "Criando ou atualizando registro $type para $name..."

  if [ "$type" == "MX" ]; then
    data=$(jq -n --arg type "$type" --arg name "$name" --arg content "$content" --arg ttl "$ttl" --argjson proxied false --arg priority "$priority" \
          '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber), proxied: $proxied, priority: ($priority | tonumber)}')
  else
    data=$(jq -n --arg type "$type" --arg name "$name" --arg content "$content" --arg ttl "$ttl" --argjson proxied false \
          '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber), proxied: $proxied}')
  fi

  response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
             -H "X-Auth-Email: $CloudflareEmail" \
             -H "X-Auth-Key: $CloudflareAPI" \
             -H "Content-Type: application/json" \
             --data "$data")

  success=$(echo "$response" | jq -r '.success')

  if [ "$success" == "true" ]; then
    echo "Registro $type para $name criado/atualizado com sucesso."
  else
    echo "Erro ao criar/atualizar registro $type para $name: $(echo $response | jq -r '.errors[].message')"
  fi
}

echo "Criando registros DNS..."
create_record "A" "$DKIMSelector" "$ServerIP" "120" ""
create_record "TXT" "$ServerName" "v=spf1 a:$ServerName ~all" "120" ""
create_record "TXT" "_dmarc.$ServerName" "v=DMARC1; p=quarantine; rua=mailto:dmarc@$ServerName;" "120" ""
create_record "TXT" "$DKIMSelector._domainkey.$ServerName" "v=DKIM1; h=sha256; k=rsa; p=$DKIMCode" "120" ""
create_record "MX" "$ServerName" "$ServerName" "120" "10"

echo "Configuração concluída."
