#!/bin/bash

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

# Instalação dos pacotes necessários
sudo apt-get install opendkim -y && sudo apt-get install opendkim-tools -y

# Criação dos diretórios necessários
sudo mkdir -p /etc/opendkim/keys

# Configuração de permissões e propriedade
sudo chown -R opendkim:opendkim /etc/opendkim/
sudo chmod 700 /etc/opendkim/keys

# Configuração do arquivo default do OpenDKIM
echo "RUNDIR=/run/opendkim
SOCKET=\"inet:9982@localhost\"
USER=opendkim
GROUP=opendkim
PIDFILE=\$RUNDIR/\$NAME.pid
EXTRAAFTER=" | sudo tee /etc/default/opendkim > /dev/null

# Configuração do arquivo de configuração do OpenDKIM
echo "AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   007
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes
Canonicalization        relaxed/relaxed
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                  opendkim:opendkim
Domain                  ${ServerName}
KeyFile                 /etc/opendkim/keys/${DKIMSelector}.private
Selector                ${DKIMSelector}
Socket                  inet:9982@localhost
RequireSafeKeys         false" | sudo tee /etc/opendkim.conf > /dev/null

# Definição dos hosts confiáveis para o DKIM
echo "127.0.0.1
localhost
$ServerName
*.$Domain" | sudo tee /etc/opendkim/TrustedHosts > /dev/null

# Geração das chaves DKIM
sudo opendkim-genkey -b 2048 -s $DKIMSelector -d $ServerName -D /etc/opendkim/keys/

# Configuração da KeyTable e SigningTable
echo "$DKIMSelector._domainkey.$ServerName $ServerName:$DKIMSelector:/etc/opendkim/keys/$DKIMSelector.private" | sudo tee /etc/opendkim/KeyTable > /dev/null
echo "*@$ServerName $DKIMSelector._domainkey.$ServerName" | sudo tee /etc/opendkim/SigningTable > /dev/null

# Ajuste de permissões e propriedade das chaves
sudo chown -R opendkim:opendkim /etc/opendkim/keys
sudo chmod 600 /etc/opendkim/keys/*
sudo chmod 700 /etc/opendkim/keys

sudo chown opendkim:opendkim /etc/opendkim/KeyTable
sudo chmod 644 /etc/opendkim/KeyTable

sudo chown opendkim:opendkim /etc/opendkim/SigningTable
sudo chmod 644 /etc/opendkim/SigningTable

sudo chown -R opendkim:opendkim /etc/opendkim/keys
sudo chmod -R 700 /etc/opendkim/keys


# Adiciona as chaves ao KeyTable e SigningTable
sudo cp /etc/opendkim/keys/$DKIMSelector.txt /root/dkim.txt && sudo chmod 600 /root/dkim.txt

# Código para processar a chave DKIM
DKIMFileCode=$(cat /root/dkim.txt)

echo '#!/usr/bin/node

const DKIM = `'$DKIMFileCode'`
console.log(DKIM.replace(/(\r\n|\n|\r|\t|"|\)| )/gm, "").split(";").find((c) => c.match("p=")).replace("p=",""))

' | sudo tee /root/dkimcode.sh > /dev/null

sudo chmod 700 /root/dkimcode.sh

echo "==================================================================== DKIM ==============================================================================="

echo "==================================================== POSTFIX ===================================================="

sleep 3

# Atualiza a lista de pacotes
sudo apt-get update

# Instala o Postfix e pacotes adicionais
sudo DEBIAN_FRONTEND=noninteractive apt-get install --assume-yes postfix postfix-policyd-spf-python opendmarc

# Configurações básicas do Postfix
debconf-set-selections <<< "postfix postfix/mailname string $ServerName"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
debconf-set-selections <<< "postfix postfix/destinations string $ServerName, localhost"
sudo dpkg-reconfigure -f noninteractive postfix

# Atualiza o arquivo main.cf
sudo tee /etc/postfix/main.cf > /dev/null <<EOF
myhostname = $ServerName
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no
readme_directory = no
compatibility_level = 3.6

# DKIM Settings
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:9982
non_smtpd_milters = inet:localhost:9982

# SPF Settings
smtpd_recipient_restrictions = 
  permit_mynetworks,
  permit_sasl_authenticated,
  permit

# TLS parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/$ServerName/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/$ServerName/privkey.pem
smtpd_tls_security_level = may
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s
smtpd_tls_protocols =!SSLv2,!SSLv3,!TLSv1,!TLSv1.1, TLSv1.2
smtpd_tls_ciphers = medium
smtpd_tls_exclude_ciphers = aNULL, MD5
smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache

alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = $ServerName, localhost
relayhost =
mynetworks = $ServerName 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

smtpd_helo_required = yes
smtpd_helo_restrictions = 
  permit

smtpd_sender_restrictions = 
  permit

smtpd_client_restrictions = 
  permit

smtpd_data_restrictions = 
  permit
EOF

# Atualiza o arquivo access.recipients
echo -e "$ServerName OK" | sudo tee /etc/postfix/access.recipients > /dev/null

# Criação do arquivo de configuração do policyd-spf
sudo tee /etc/postfix-policyd-spf-python/policyd-spf.conf > /dev/null <<EOF
HELO_reject = False
Mail_From_reject = False
Rcpt_To_reject = True
EOF


# Criar os diretórios necessários para o OpenDMARC
sudo mkdir -p /run/opendmarc
sudo mkdir -p /etc/opendmarc
sudo mkdir -p /var/log/opendmarc
sudo mkdir -p /var/lib/opendmarc

# Ajustar permissões e propriedade dos diretórios
sudo chown opendmarc:opendmarc /run/opendmarc
sudo chmod 750 /run/opendmarc
sudo chown opendmarc:opendmarc /etc/opendmarc
sudo chmod 750 /etc/opendmarc
sudo chown opendmarc:opendmarc /var/log/opendmarc
sudo chmod 750 /var/log/opendmarc
sudo chown opendmarc:opendmarc /var/lib/opendmarc
sudo chmod 750 /var/lib/opendmarc

# Criar o arquivo de configuração do OpenDMARC
sudo tee /etc/opendmarc.conf > /dev/null <<EOF
# Configuração de logs
Syslog true

# Definição do socket onde o OpenDMARC escuta
Socket inet:54321@localhost

# Definição do arquivo PID para controle do processo
PidFile /run/opendmarc/opendmarc.pid

# ID do autenticador usado nos cabeçalhos de autenticação
AuthservID OpenDMARC

# Localização do arquivo de hosts a serem ignorados
IgnoreHosts /etc/opendmarc/ignore.hosts

# Definição de se rejeitar falhas de DMARC
RejectFailures false

# IDs de servidores de autenticação confiáveis
TrustedAuthservIDs ${ServerName}

# Arquivo de histórico para relatórios detalhados
HistoryFile /var/lib/opendmarc/opendmarc.dat
EOF

# Criar o arquivo de hosts a serem ignorados se não existir
sudo touch /etc/opendmarc/ignore.hosts
sudo chown opendmarc:opendmarc /etc/opendmarc/ignore.hosts
sudo chmod 644 /etc/opendmarc/ignore.hosts

# Criar o arquivo de histórico do OpenDMARC
sudo touch /var/lib/opendmarc/opendmarc.dat
sudo chown opendmarc:opendmarc /var/lib/opendmarc/opendmarc.dat
sudo chmod 644 /var/lib/opendmarc/opendmarc.dat

# Criar o arquivo PID do OpenDMARC
sudo touch /run/opendmarc/opendmarc.pid
sudo chown opendmarc:opendmarc /run/opendmarc/opendmarc.pid
sudo chmod 600 /run/opendmarc/opendmarc.pid

# Reiniciar os serviços do Postfix e Dovecot
sudo systemctl restart postfix
sudo systemctl enable postfix

# Configurar e reiniciar o OpenDKIM
sudo systemctl restart opendkim
sudo systemctl enable opendkim

# Configurar e reiniciar o OpenDMARC
sudo systemctl restart opendmarc
sudo systemctl enable opendmarc

echo "==================================================== POSTFIX ===================================================="

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
     --data '{ "type": "TXT", "name": "'$ServerName'", "content": "v=spf1 a:'$ServerName' ~all", "ttl": 120, "proxied": false }'

echo "  -- Cadastrando DMARK"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "_dmarc.'$ServerName'", "content": "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc-reports@'$ServerName'; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r", "ttl": 120, "proxied": false }'

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

echo "==================================================== APPLICATION ===================================================="

cd /root && npm install && pm2 start server.js && pm2 startup && pm2 save

npm install axios dotenv events

# Instala Apache, PHP e módulos necessários
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install apache2 php php-cli php-dev php-curl php-gd libapache2-mod-php --assume-yes

# Verifica a existência do diretório /var/www/html
if [ ! -d "/var/www/html" ]; then
    echo "Folder /var/www/html does not exist"
    exit 1
fi

# Install php-mbstring extension
sudo apt-get install php-mbstring -y

# Restart Apache service
sudo /etc/init.d/apache2 restart

echo "==================================================== APPLICATION ===================================================="

echo "================================= Todos os comandos foram executados com sucesso! ==================================="

echo "======================================================= FIM =========================================================="

# Reiniciar servidor
echo "Reiniciando o servidor em 5 segundos..."
sleep 5
sudo reboot


