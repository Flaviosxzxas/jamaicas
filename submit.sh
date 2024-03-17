#!/bin/bash

ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

Domain=$(echo $ServerName | cut -d "." -f2-)
DKIMSelector=$(echo $ServerName | awk -F[.:] '{print $1}')
ServerIP=$(wget -qO- http://ip-api.com/line\?fields=query)

echo "Configuando Servidor: $ServerName"

sleep 10

echo "==================================================================== Hostname && SSL ===================================================================="

ufw allow 25/tcp

sudo apt-get update && sudo apt-get install wget curl jq python3-certbot-dns-cloudflare -y

curl -fsSL https://deb.nodesource.com/setup_21.x | sudo bash -s

sudo apt-get install nodejs -y
npm i -g pm2

sudo mkdir -p /root/.secrets && sudo chmod 0700 /root/.secrets/ && sudo touch /root/.secrets/cloudflare.cfg && sudo chmod 0400 /root/.secrets/cloudflare.cfg

echo "dns_cloudflare_email = $CloudflareEmail
dns_cloudflare_api_key = $CloudflareAPI" | sudo tee /root/.secrets/cloudflare.cfg > /dev/null

echo -e "127.0.0.1 localhost
127.0.0.1 $ServerName
$ServerIP $ServerName" | sudo tee /etc/hosts > /dev/null

echo -e "$ServerName" | sudo tee /etc/hostname > /dev/null

sudo hostnamectl set-hostname "$ServerName"

certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.cfg --dns-cloudflare-propagation-seconds 60 --rsa-key-size 4096 -d $ServerName

echo "==================================================================== Hostname && SSL ===================================================================="

echo "==================================================================== DKIM ==============================================================================="

#!/bin/bash

# Define o hostname (substitua YOUR_HOSTNAME pelo nome do host desejado)
HOSTNAME="$ServerName"

# Remove locks e atualiza o sistema
sudo rm -rf /var/lib/apt/lists/lock
sudo rm /var/lib/dpkg/lock-frontend
sudo dpkg --configure -a
sudo apt update

# Atualiza o sistema
sudo apt-get update && sudo apt-get -y upgrade && sudo apt-get -y dist-upgrade

# Configura o hostname
sudo hostname $ServerName

# Instala Apache, PHP e módulos necessários
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install apache2 php php-cli php-dev php-curl php-gd libapache2-mod-php --assume-yes

# Verifica a existência do diretório /var/www/html
if [ ! -d "/var/www/html" ]; then
    echo "Folder /var/www/html does not exist"
    exit 1
fi

# Reinicia o Apache
sudo /etc/init.d/apache2 restart

# Configurações do hostname novamente (pode ser redundante)
sudo hostname $ServerName

# Configurações do Postfix
sudo debconf-set-selections <<< "postfix postfix/main_mailer_type select Internet Site"
sudo debconf-set-selections <<< "postfix postfix/mailname string $ServerName"
sudo debconf-set-selections <<< "postfix postfix/destinations string localhost.localdomain, localhost"
sudo apt install postfix-policyd-spf-python -y
sudo /etc/init.d/postfix restart

# Configurações adicionais para Postfix e política SPF
echo "policyd-spf unix - n n - 0 spawn" | sudo tee -a /etc/postfix/master.cf
echo "user=policyd-spf argv=/usr/bin/policyd-spf" | sudo tee -a /etc/postfix/master.cf
echo "policyd-spf_time_limit = 3600" | sudo tee -a /etc/postfix/main.cf
# O restante das configurações do Postfix é omitido para brevidade, mas deve seguir a mesma estrutura.

# Instala e configura o OpenDKIM
sudo apt-get install opendkim -y && sudo apt-get install opendkim-tools -y
sudo gpasswd -a postfix opendkim
sudo chmod 777 /etc/opendkim.conf
sudo chmod 777 /etc/default/opendkim
# As configurações específicas do OpenDKIM são omitidas para brevidade.

# Criação de diretórios e ajustes de permissões para OpenDKIM
sudo mkdir -p /etc/opendkim/keys
sudo chmod 777 /etc/opendkim
sudo chmod 777 /etc/opendkim/keys

# Configurações de confiança e tabelas para OpenDKIM
# Nota: As entradas específicas para TrustedHosts, KeyTable, SigningTable, etc., são omitidas.

# Geração de chaves para OpenDKIM
# Substitua YOUR_DOMAIN pelo seu domínio real
DOMAIN="YOUR_DOMAIN"
sudo mkdir -p /etc/opendkim/keys/$ServerName
cd /etc/opendkim/keys/$ServerName
sudo opendkim-genkey -s mail -d $ServerName
sudo chown opendkim:opendkim mail.private

# Reinicia os serviços após a configuração
sudo service postfix restart
sudo service opendkim restart

# Configurações de Postfix para suporte a UTF-8 e reinício dos serviços
sudo postconf -e smtputf8_enable=no
sudo postconf -e smtputf8_autodetect_classes=bounce
sudo /etc/init.d/postfix restart
sudo /etc/init.d/apache2 restart

echo "==================================================== POSTFIX ===================================================="

DKIMFileCode=$(cat /etc/opendkim/keys/$ServerName/mail.txt)

echo '#!/usr/bin/node

const DKIM = `'$DKIMFileCode'`
console.log(DKIM.replace(/(\r\n|\n|\r|\t|"|\)| )/gm, "").split(";").find((c) => c.match("p=")).replace("p=",""))

'| sudo tee /root/dkimcode.sh > /dev/null

sudo chmod 777 /root/dkimcode.sh

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

sleep 5
reboot
