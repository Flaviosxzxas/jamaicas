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

# Definir variáveis principais
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

# Ajuste de permissões e propriedade das chaves
sudo chmod -R 750 /etc/opendkim/

# Código para processar a chave DKIM
DKIMFileCode=$(cat /etc/opendkim/keys/mail.txt)

# Criar o script para extrair a chave pública
echo '#!/usr/bin/node

const DKIM = `'"$DKIMFileCode"'`;

// Remove quebras de linha, espaços e caracteres indesejados
const publicKey = DKIM.replace(/(\r\n|\n|\r|\t|"|\)| )/gm, "").split(";").find((c) => c.match("p=")).replace("p=", "");

console.log(publicKey);
' | sudo tee /root/dkimcode.sh > /dev/null

# Dar permissão de execução ao script
sudo chmod 755 /root/dkimcode.sh

echo "==================================================== CLOUDFLARE ===================================================="

# DKIM
DKIMCode=$(/root/dkimcode.sh)

# Obter o ID da Zona
CloudflareZoneID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$Domain&status=active" \
  -H "X-Auth-Email: $CloudflareEmail" \
  -H "X-Auth-Key: $CloudflareAPI" \
  -H "Content-Type: application/json" | jq -r '.result[0].id')

if [ -z "$CloudflareZoneID" ]; then
  echo "Erro: Não foi possível obter o ID da zona do Cloudflare."
  exit 1
fi

# Função para criar ou atualizar registros DNS
create_or_update_record() {
  local record_type=$1
  local record_name=$2
  local record_content=$3
  local record_ttl=120
  local record_priority=$4
  local record_proxied=false

  echo "  -- Criando ou atualizando registro $record_type para $record_name"

  # Verificar se o registro já existe
  existing_record=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records?name=$record_name&type=$record_type" \
    -H "X-Auth-Email: $CloudflareEmail" \
    -H "X-Auth-Key: $CloudflareAPI" \
    -H "Content-Type: application/json" | jq -r '.result[0].id')

  # Atualizar ou criar o registro
  if [ -n "$existing_record" ]; then
    # Atualizar registro existente
    echo "Registro existente encontrado. Atualizando..."
    curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records/$existing_record" \
      -H "X-Auth-Email: $CloudflareEmail" \
      -H "X-Auth-Key: $CloudflareAPI" \
      -H "Content-Type: application/json" \
      --data '{
        "type": "'"$record_type"'",
        "name": "'"$record_name"'",
        "content": "'"$record_content"'",
        "ttl": '"$record_ttl"',
        "proxied": '"$record_proxied"'
      }'
  else
    # Criar novo registro
    echo "Nenhum registro existente encontrado. Criando novo..."
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
      -H "X-Auth-Email: $CloudflareEmail" \
      -H "X-Auth-Key: $CloudflareAPI" \
      -H "Content-Type: application/json" \
      --data '{
        "type": "'"$record_type"'",
        "name": "'"$record_name"'",
        "content": "'"$record_content"'",
        "ttl": '"$record_ttl"',
        "proxied": '"$record_proxied"'
      }'
  fi
}

# Adicionar ou atualizar registros
create_or_update_record "A" "$DKIMSelector" "$ServerIP" ""
create_or_update_record "TXT" "$ServerName" "v=spf1 a:$ServerName ~all" ""
create_or_update_record "TXT" "_dmarc.$ServerName" "v=DMARC1; p=reject; rua=mailto:dmarc-reports@$ServerName; sp=reject; adkim=s; aspf=s" ""
create_or_update_record "TXT" "mail._domainkey.$ServerName" "v=DKIM1; h=sha256; k=rsa; p=$DKIMCode" ""
create_or_update_record "MX" "$ServerName" "$ServerName" "10"


