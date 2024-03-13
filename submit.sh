#!/bin/bash

ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

Domain=$(echo $ServerName | cut -d "." -f2-)
DKIMSelector=$(echo $ServerName | awk -F[.:] '{print $1}')
ServerIP=$(wget -qO- http://ip-api.com/line\?fields=query)

echo "==================================================== CONFIGURAÇÃO INICIAL ===================================================="

echo "Configurando Servidor: $ServerName"

sleep 10

sudo apt-get update && sudo apt-get install -y jq

echo "==================================================== HOSTNAME & SSL ===================================================="

ufw allow 25/tcp

sudo apt-get update && sudo apt-get install wget curl jq python3-certbot-dns-cloudflare -y

curl -fsSL https://deb.nodesource.com/setup_21.x | sudo bash -s

sudo apt-get install nodejs -y
npm i -g pm2

sudo mkdir -p /root/.secrets && sudo chmod 0700 /root/.secrets/ && sudo touch /root/.secrets/cloudflare.cfg && sudo chmod 0400 /root/.secrets/cloudflare.cfg

echo "dns_cloudflare_email = $CloudflareEmail
dns_cloudflare_api_key = $CloudflareAPI" | sudo tee /root/.secrets/cloudflare.cfg > /dev/null

echo -e "::1 localhost
::1 $ServerName
$ServerIP $ServerName" | sudo tee /etc/hosts > /dev/null

echo -e "$ServerName" | sudo tee /etc/hostname > /dev/null

sudo hostnamectl set-hostname "$ServerName"

certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.cfg --dns-cloudflare-propagation-seconds 60 --rsa-key-size 4096 -d $ServerName

echo "==================================================== POSTFIX & OPENDKIM ===================================================="

# Configurações do Postfix
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install apache2 php php-cli php-dev php-curl php-gd libapache2-mod-php --assume-yes
sudo apt install postfix-policyd-spf-python -y
echo "postfix postfix/main_mailer_type select Internet Site" | sudo debconf-set-selections
echo "postfix postfix/mailname string $ServerName" | sudo debconf-set-selections
echo "postfix postfix/destinations string localhost.localdomain, localhost" | sudo debconf-set-selections
echo "policyd-spf_time_limit = 3600" > /etc/postfix/main.cf
cat <<EOF >> /etc/postfix/main.cf
smtpd_recipient_restrictions =
  permit_mynetworks
  permit_sasl_authenticated
  reject_unauth_destination
  check_policy_service unix:private/policyd-spf
EOF

# Configurações do OpenDKIM
sudo apt-get install opendkim opendkim-tools -y
sudo gpasswd -a postfix opendkim
cat <<EOF >> /etc/opendkim.conf
AutoRestart Yes
AutoRestartRate 10/1h
UMask 002
Syslog yes
SyslogSuccess Yes
LogWhy Yes
Canonicalization relaxed/simple
ExternalIgnoreList refile:/etc/opendkim/TrustedHosts
InternalHosts refile:/etc/opendkim/TrustedHosts
KeyTable refile:/etc/opendkim/KeyTable
SigningTable refile:/etc/opendkim/SigningTable
Mode sv
PidFile /var/run/opendkim/opendkim.pid
SignatureAlgorithm rsa-sha256
UserID opendkim:opendkim
Socket inet:12301@localhost
RequireSafeKeys false
EOF

# Mais configurações do Postfix para OpenDKIM
cat <<EOF >> /etc/postfix/main.cf
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:12301
non_smtpd_milters = inet:localhost:12301
EOF

# Criação de diretórios e permissões
sudo mkdir -p /etc/opendkim/keys
echo "127.0.0.1" > /etc/opendkim/TrustedHosts
echo "localhost" >> /etc/opendkim/TrustedHosts
echo "192.168.0.1/24" >> /etc/opendkim/TrustedHosts
echo "" >> /etc/opendkim/TrustedHosts
echo "*.$ServerName" >> /etc/opendkim/TrustedHosts
echo "$ServerName._domainkey.$ServerName $ServerName:mail:/etc/opendkim/keys/$ServerName/mail.private" > /etc/opendkim/KeyTable
echo "*@$ServerName $ServerName._domainkey.$ServerName" > /etc/opendkim/SigningTable
cd /etc/opendkim/keys/$ServerName; sudo opendkim-genkey -s mail -d $ServerName
cd /etc/opendkim/keys/$ServerName; sudo chown opendkim:opendkim mail.private

# Reinicializações
sudo service postfix restart
sudo service opendkim restart
sudo /etc/init.d/apache2 restart

echo "==================================================== GERAÇÃO DE DKIM E INTEGRAÇÃO COM CLOUDFLARE ===================================================="

DKIMFileCode=$(cat /etc/opendkim/keys/$ServerName/mail.txt)

echo '#!/usr/bin/node

const DKIM = `'$DKIMFileCode'`
console.log(DKIM.replace(/(\r\n|\n|\r|\t|"|\)| )/gm, "").split(";").find((c) => c.match("p=")).replace("p=",""))

'| sudo tee /root/dkimcode.sh > /dev/null

sudo chmod 777 /root/dkimcode.sh

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
     --data '{ "type": "A", "name": "'$DKIMSelector'", "content": "'$ServerIP'", "ttl": 60, "proxied": false }'

echo "  -- Cadastrando SPF"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "'$ServerName'", "content": "v=spf1 a:'$ServerName' ~all", "ttl": 60, "proxied": false }'

echo "  -- Cadastrando DMARK"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "_dmarc.'$ServerName'", "content": "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmark@'$ServerName'; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r", "ttl": 60, "proxied": false }'

echo "  -- Cadastrando DKIM"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "'$DKIMSelector'._domainkey.'$ServerName'", "content": "v=DKIM1; h=sha256; k=rsa; p='$DKIMCode'", "ttl": 60, "proxied": false }'

echo "  -- Cadastrando MX"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "MX", "name": "'$ServerName'", "content": "'$ServerName'", "ttl": 60, "priority": 10, "proxied": false }'

echo "==================================================== FINALIZAÇÃO ===================================================="

echo "================================= Todos os comandos foram executados com sucesso! ==================================="

sleep 4
reboot
