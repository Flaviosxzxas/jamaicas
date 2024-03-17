#!/bin/bash

# Verifica se os argumentos foram passados
if [ $# -ne 3 ]; then
    echo "Usage: $0 <ServerName> <CloudflareAPI> <CloudflareEmail>"
    exit 1
fi

ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

# Definindo variáveis adicionais
Domain=$(echo $ServerName | cut -d "." -f2-)
DKIMSelector=$(echo $ServerName | awk -F[.:] '{print $1}')
ServerIP=$(curl -s http://ip-api.com/line\?fields=query)

echo "Configurando Servidor: $ServerName"

sudo apt-get update && sudo apt-get install -y jq

# Atraso para evitar possíveis problemas de execução simultânea
sleep 10

echo "==================================================================== Hostname && SSL ===================================================================="

# Permitir tráfego na porta 25
ufw allow 25/tcp

# Atualizar pacotes e instalar dependências
sudo apt-get update && sudo apt-get install wget curl jq python3-certbot-dns-cloudflare -y
curl -fsSL https://deb.nodesource.com/setup_21.x | sudo bash -
sudo apt-get install nodejs -y
sudo npm i -g pm2

# Configurar credenciais do Cloudflare
sudo mkdir -p /root/.secrets
echo "dns_cloudflare_email=\"$CloudflareEmail\"" | sudo tee -a /root/.secrets/cloudflare.cfg > /dev/null
echo "dns_cloudflare_api_key=\"$CloudflareAPI\"" | sudo tee -a /root/.secrets/cloudflare.cfg > /dev/null
sudo chmod 600 /root/.secrets/cloudflare.cfg

# Adicionar entrada no /etc/hosts
sudo sed -i "/$ServerName/d" /etc/hosts
echo -e "$ServerIP $ServerName" | sudo tee -a /etc/hosts > /dev/null

# Configurar hostname
echo "$ServerName" | sudo tee /etc/hostname > /dev/null
sudo hostnamectl set-hostname "$ServerName"

# Obter certificado SSL usando Certbot
certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.cfg --dns-cloudflare-propagation-seconds 60 --rsa-key-size 4096 -d $ServerName

echo "==================================================================== Hostname && SSL ===================================================================="

sudo hostname $ServerName
DEBIAN_FRONTEND=noninteractive apt-get -y install apache2 php php-cli php-dev php-curl php-gd libapache2-mod-php --assume-yes

echo "==================================================================== DKIM ==============================================================================="

# Instalar pacotes e configurar serviços de e-mail
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix postfix-policyd-spf-python opendkim opendkim-tools

# Configurar opção "Internet Site" automaticamente
echo "postfix postfix/main_mailer_type select Internet Site" | sudo debconf-set-selections
echo "postfix postfix/mailname string $ServerName" | sudo debconf-set-selections

sudo systemctl start postfix
sudo systemctl enable postfix
sudo systemctl start opendkim
sudo systemctl enable opendkim

# Configurações do Postfix
sudo postconf -e 'main_mailer_type = Internet Site'
sudo postconf -e "myhostname = $ServerName"
sudo postconf -e "mydestination = localhost.localdomain, localhost, $ServerName"
sudo postconf -e "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128"
sudo postconf -e "policyd-spf_time_limit = 3600"

# Configurações adicionais do Postfix e política SPF
sudo sed -i '/policyd-spf/d' /etc/postfix/master.cf
sudo tee -a /etc/postfix/master.cf > /dev/null <<EOL
policyd-spf unix - n n - 0 spawn
  user=policyd-spf argv=/usr/bin/policyd-spf
EOL

# Configurações do OpenDKIM
sudo usermod -aG opendkim postfix
sudo mkdir -p /etc/opendkim/keys/$ServerName
sudo opendkim-genkey -s $DKIMSelector -d $ServerName
sudo chown -R opendkim:opendkim /etc/opendkim/keys/$ServerName
sudo tee /etc/opendkim.conf > /dev/null <<EOL
Syslog yes
UMask 002
Domain $ServerName
KeyTable /etc/opendkim/KeyTable
SigningTable refile:/etc/opendkim/SigningTable
Selector $DKIMSelector
Socket inet:8891@localhost
EOL

sudo tee /etc/opendkim/KeyTable > /dev/null <<EOL
$DKIMSelector._domainkey.$ServerName $ServerName:$DKIMSelector:/etc/opendkim/keys/$ServerName/$DKIMSelector.private
EOL

sudo tee /etc/opendkim/SigningTable > /dev/null <<EOL
*@$ServerName $DKIMSelector._domainkey.$ServerName
EOL

# Reiniciar serviços
sudo systemctl restart postfix
sudo systemctl restart opendkim

echo "==================================================== POSTFIX ===================================================="

# Extraindo código DKIM
DKIMCode=$(sudo opendkim-testkey -d $ServerName -s $DKIMSelector | grep "public key" | awk '{print $3}')

echo '#!/usr/bin/env node
console.log(process.argv[2].replace(/(\r\n|\n|\r|\t|"|\)| )/gm, "").split(";").find(c => c.match("p=")).replace("p=",""));
' | sudo tee /usr/local/bin/dkimcode > /dev/null
sudo chmod +x /usr/local/bin/dkimcode

DKIMRecord=$(sudo dkimcode "v=DKIM1; h=sha256; k=rsa; p=$DKIMCode")

echo "==================================================== CLOUDFLARE ===================================================="

DKIMCode=$(/root/dkimcode.sh)

sleep 5

echo "  -- Obtendo Zona"
CloudflareZoneID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$Domain&status=active" \
  -H "X-Auth-Email: $CloudflareEmail" \
  -H "X-Auth-Key: $CloudflareAPI" \
  -H "Content-Type: application/json" | jq -r '{"result"}[] | .[0] | .id')
  
echo "  -- Cadastrando A"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "A", "name": "'$DKIMSelector'", "content": "'$ServerIP'", "ttl": 120, "proxied": false }'

echo "  -- Cadastrando SPF"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "'$ServerName'", "content": "v=spf1 a:'$ServerName' a mx ~all", "ttl": 120, "proxied": false }'

echo "  -- Cadastrando DMARK"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "_dmarc.'$ServerName'", "content": "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmark@'$ServerName'; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r", "ttl": 120, "proxied": false }'

echo "  -- Cadastrando DKIM"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "'$DKIMSelector'._domainkey.'$ServerName'", "content": "v=DKIM1; h=sha256; k=rsa; p='$DKIMCode'", "ttl": 120, "proxied": false }'

echo "  -- Cadastrando MX"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "MX", "name": "'$ServerName'", "content": "'$ServerName'", "ttl": 120, "priority": 10, "proxied": false }'

echo "==================================================== CLOUDFLARE ===================================================="

echo "================================= Todos os comandos foram executados com sucesso! ==================================="

# Reiniciar servidor
echo "Reiniciando o servidor em 5 segundos..."
sleep 5
reboot
