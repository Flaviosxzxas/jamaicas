#!/bin/bash

ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

Domain=$(echo $ServerName | cut -d "." -f2-)
DKIMSelector=$(echo $ServerName | awk -F[.:] '{print $1}')
ServerIP=$(wget -qO- http://ip-api.com/line\?fields=query)

echo "Configurando Servidor: $ServerName"

sleep 10

sudo apt-get update && sudo apt-get install -y jq

echo "==================================================================== Hostname && SSL ===================================================================="

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

echo "==================================================================== Hostname && SSL ===================================================================="


sudo apt-get update
sudo hostname $ServerName
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install apache2 php php-cli php-dev php-curl php-gd libapache2-mod-php --assume-yes
if [ -d "/var/www/html" ]; then echo "Folder exists"; else echo "Folder does not exist"; fi
sudo systemctl restart apache2
sudo hostname $ServerName
echo "postfix postfix/main_mailer_type select Internet Site" | sudo debconf-set-selections
echo "postfix postfix/mailname string $ServerName" | sudo debconf-set-selections
echo "postfix postfix/destinations string localhost.localdomain, localhost" | sudo debconf-set-selections

sudo apt install postfix-policyd-spf-python -y
sudo systemctl restart postfix

echo "policyd-spf unix - n n - 0 spawn" | sudo tee -a /etc/postfix/master.cf
echo "user=policyd-spf argv=/usr/bin/policyd-spf" | sudo tee -a /etc/postfix/master.cf
echo "policyd-spf_time_limit = 3600" | sudo tee -a /etc/postfix/main.cf

echo "smtpd_recipient_restrictions =
permit_mynetworks,
permit_sasl_authenticated,
reject_unauth_destination,
check_policy_service unix:private/policyd-spf" | sudo tee -a /etc/postfix/main.cf

sudo systemctl restart postfix
sudo systemctl restart apache2

sudo apt-get install opendkim opendkim-tools -y
sudo gpasswd -a postfix opendkim

sudo chmod 640 /etc/opendkim.conf
sudo chmod 640 /etc/default/opendkim
sudo chmod 640 /etc/postfix/main.cf

{
    echo "AutoRestart Yes"
    echo "AutoRestartRate 10/1h"
    echo "UMask 002"
    echo "Syslog yes"
    echo "SyslogSuccess Yes"
    echo "LogWhy Yes"
    echo "Canonicalization relaxed/simple"
    echo "ExternalIgnoreList refile:/etc/opendkim/TrustedHosts"
    echo "InternalHosts refile:/etc/opendkim/TrustedHosts"
    echo "KeyTable refile:/etc/opendkim/KeyTable"
    echo "SigningTable refile:/etc/opendkim/SigningTable"
    echo "Mode sv"
    echo "PidFile /var/run/opendkim/opendkim.pid"
    echo "SignatureAlgorithm rsa-sha256"
    echo "UserID opendkim:opendkim"
    echo "Socket inet:12301@localhost"
    echo "RequireSafeKeys false"
} | sudo tee -a /etc/opendkim.conf

echo "SOCKET=\"inet:12301@localhost\"" | sudo tee /etc/default/opendkim

{
    echo "milter_protocol = 2"
    echo "milter_default_action = accept"
    echo "smtpd_milters = inet:localhost:12301"
    echo "non_smtpd_milters = inet:localhost:12301"
} | sudo tee -a /etc/postfix/main.cf

sudo mkdir -p /etc/opendkim/keys
echo "127.0.0.1
localhost
192.168.0.1/24
*.$ServerName" | sudo tee /etc/opendkim/TrustedHosts

echo "$ServerName._domainkey.$ServerName $ServerName:mail:/etc/opendkim/keys/$ServerName/mail.private" | sudo tee /etc/opendkim/KeyTable
echo "*@$ServerName $ServerName._domainkey.$ServerName" | sudo tee /etc/opendkim/SigningTable

sudo mkdir -p /etc/opendkim/keys/$ServerName
cd /etc/opendkim/keys/$ServerName && sudo opendkim-genkey -s mail -d $ServerName
cd /etc/opendkim/keys/$ServerName && sudo chown opendkim:opendkim mail.private
sudo chown -R opendkim:opendkim /etc/opendkim

sudo chmod o=- /etc/opendkim/keys
sudo chmod o=- /etc/opendkim/keys/$ServerName/mail.private

# Adicionando parâmetros de TLS ao Postfix
sudo postconf -e "smtpd_tls_cert_file=/etc/letsencrypt/live/$ServerName/fullchain.pem"
sudo postconf -e "smtpd_tls_key_file=/etc/letsencrypt/live/$ServerName/privkey.pem"
sudo postconf -e "smtpd_tls_security_level=may"
sudo postconf -e "smtp_tls_CApath=/etc/ssl/certs"
sudo postconf -e "smtp_tls_security_level=may"
sudo postconf -e "smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache"

sudo systemctl restart postfix
sudo systemctl restart opendkim
sudo cat /etc/opendkim/keys/$ServerName/mail.txt

sudo chmod o=- /var/www/html
sudo chmod o=- /var/www
sudo rm -f /var/www/html/*.html

sudo postconf -e smtputf8_enable=no
sudo postconf -e smtputf8_autodetect_classes=bounce

echo "==================================================== CLOUDFLARE ===================================================="

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

echo "==================================================== CLOUDFLARE ===================================================="

echo "==================================================== APPLICATION ===================================================="

echo "================================= Todos os comandos foram executados com sucesso! ==================================="

sleep 4
reboot
