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

# Atualiza a lista de pacotes
sudo apt-get update

# Define o nome do host
sudo hostname $ServerName

# Instalação do Apache e PHP
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install apache2 php php-cli php-dev php-curl php-gd libapache2-mod-php --assume-yes

# Verifica se o diretório /var/www/html existe
if [ -d "/var/www/html" ]; then
    echo "Folder exists"
else
    echo "Folder does not exist"
fi

# Reinicia o serviço do Apache
/etc/init.d/apache2 restart

# Reinicia o serviço do Apache
sudo hostname $ServerName

# Configuração do Postfix
echo "postfix postfix/main_mailer_type select Internet Site" | sudo debconf-set-selections
echo "postfix postfix/mailname string $ServerName" | sudo debconf-set-selections
echo "postfix postfix/destinations string localhost.localdomain, localhost" | sudo debconf-set-selections
sudo apt install postfix-policyd-spf-python -y
sudo /etc/init.d/postfix restart

# Configuração do SPF
sudo echo "policyd-spf unix - n n - 0 spawn" >> /etc/postfix/master.cf
sudo echo "user=policyd-spf argv=/usr/bin/policyd-spf" >> /etc/postfix/master.cf
sudo echo "policyd-spf_time_limit = 3600" >> /etc/postfix/main.cf
sudo echo "smtpd_recipient_restrictions =" >> /etc/postfix/main.cf
sudo echo "permit_mynetworks," >> /etc/postfix/main.cf
sudo echo "permit_sasl_authenticated," >> /etc/postfix/main.cf
sudo echo "reject_unauth_destination," >> /etc/postfix/main.cf
sudo echo "check_policy_service unix:private/policyd-spf" >> /etc/postfix/main.cf
sudo service postfix restart

# Reinicia o serviço do Apache
sudo /etc/init.d/apache2 restart

# Instalação e configuração do OpenDKIM
sudo apt-get install opendkim -y && sudo apt-get install opendkim-tools -y
sudo gpasswd -a postfix opendkim
sudo chmod 777 /etc/opendkim.conf
sudo chmod 777 /etc/default/opendkim

# Configurações do OpenDKIM
sudo echo "AutoRestart Yes" >> /etc/opendkim.conf
sudo echo "AutoRestartRate 10/1h" >> /etc/opendkim.conf
sudo echo "UMask 002" >> /etc/opendkim.conf
sudo echo "Syslog yes" >> /etc/opendkim.conf
sudo echo "SyslogSuccess Yes" >> /etc/opendkim.conf
sudo echo "LogWhy Yes" >> /etc/opendkim.conf
sudo echo "Canonicalization relaxed/simple" >> /etc/opendkim.conf
sudo echo "ExternalIgnoreList refile:/etc/opendkim/TrustedHosts" >> /etc/opendkim.conf
sudo echo "InternalHosts refile:/etc/opendkim/TrustedHosts" >> /etc/opendkim.conf
sudo echo "KeyTable refile:/etc/opendkim/KeyTable" >> /etc/opendkim.conf
sudo echo "SigningTable refile:/etc/opendkim/SigningTable" >> /etc/opendkim.conf
sudo echo "Mode sv" >> /etc/opendkim.conf
sudo echo "PidFile /var/run/opendkim/opendkim.pid" >> /etc/opendkim.conf
sudo echo "SignatureAlgorithm rsa-sha256" >> /etc/opendkim.conf
sudo echo "UserID opendkim:opendkim" >> /etc/opendkim.conf
sudo echo "Socket inet:12301@localhost" >> /etc/opendkim.conf
sudo echo "RequireSafeKeys false" >> /etc/opendkim.conf
sudo echo "SOCKET="inet:12301@localhost"" >> /etc/default/opendkim

# Configurações do Postfix para o OpenDKIM
sudo echo "milter_protocol = 2" >> /etc/postfix/main.cf
sudo echo "milter_default_action = accept" >> /etc/postfix/main.cf
sudo echo "smtpd_milters = inet:localhost:12301" >> /etc/postfix/main.cf
sudo echo "non_smtpd_milters = inet:localhost:12301" >> /etc/postfix/main.cf

# Criação de diretórios e configurações do OpenDKIM
sudo mkdir /etc/opendkim
sudo mkdir /etc/opendkim/keys
sudo chmod 777 /etc/opendkim
sudo chmod 777 /etc/opendkim/keys

sudo echo "127.0.0.1" > /etc/opendkim/TrustedHosts
sudo echo "localhost" >> /etc/opendkim/TrustedHosts
sudo echo "192.168.0.1/24" >> /etc/opendkim/TrustedHosts
sudo echo "" >> /etc/opendkim/TrustedHosts
sudo echo "*.$ServerName" >> /etc/opendkim/TrustedHosts
sudo echo "mail._domainkey.$ServerName $ServerName:mail:/etc/opendkim/keys/$ServerName/mail.private" > /etc/opendkim/KeyTable
sudo echo "*@$ServerName mail._domainkey.$ServerName" > /etc/opendkim/SigningTable
sudo mkdir /etc/opendkim/keys/$ServerName
cd /etc/opendkim/keys/$ServerName; sudo opendkim-genkey -s mail -d $ServerName
cd /etc/opendkim/keys/$ServerName; sudo chown opendkim:opendkim mail.private
sudo chown -R opendkim:opendkim /etc/opendkim
sudo chmod go-rw /etc/opendkim/keys
sudo chmod 777 /etc/opendkim/keys/$ServerName/mail.private
sudo chmod 777 /etc/opendkim/keys/$ServerName

# Reinicia os serviços do Postfix e OpenDKIM
sudo service postfix restart
sudo service opendkim restart

# Visualiza a chave pública gerada pelo OpenDKIM
sudo cat /etc/opendkim/keys/$ServerName/mail.txt

# Configura permissões para o diretório /var/www/html
sudo chmod 777 /var/www/html
sudo chmod 777 /var/www
sudo rm /var/www/html/*.html

# Envio de arquivo (substitua [ENVIAR_ARQUIVO] pelo comando de envio)

# Configurações adicionais do Postfix
sudo postconf -e smtputf8_enable=no
sudo postconf -e smtputf8_autodetect_classes=bounce
sudo /etc/init.d/postfix restart

# Reinicia o serviço do Apache
sudo /etc/init.d/apache2 restart

echo "==================================================== CLOUDFLARE ===================================================="

# Extraindo código DKIM
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
     --data '{ "type": "MX", "name": "'$ServerName'", "content": "'mx.$Domain'", "ttl": 60, "priority": 10, "proxied": false }'

echo "==================================================== CLOUDFLARE ===================================================="

echo "==================================================== APPLICATION ===================================================="


echo "================================= Todos os comandos foram executados com sucesso! ==================================="

# Reiniciar servidor
echo "Reiniciando o servidor em 5 segundos..."
sleep 5

sudo reboot
