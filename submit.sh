#!/bin/bash

ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

=$(echo $ServerName | cut -d "." -f2-)
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

sudo apt-get install opendkim -y && sudo apt-get install opendkim-tools -y
sudo mkdir -p /etc/opendkim && sudo mkdir -p /etc/opendkim/keys
sudo chmod -R 777 /etc/opendkim/ && sudo chown -R opendkim:opendkim /etc/opendkim/

echo "RUNDIR=/run/opendkim
SOCKET=\"inet:9982@localhost\"
USER=opendkim
GROUP=opendkim
PIDFILE=\$RUNDIR/\opendkim.pid
EXTRAAFTER=" | sudo tee /etc/default/opendkim > /dev/null

echo "AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
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
Domain                  $ServerName
KeyFile                  /etc/opendkim/keys/$DKIMSelector.private
Selector                 $DKIMSelector
Socket                  inet:9982@localhost
RequireSafeKeys false" | sudo tee /etc/opendkim.conf > /dev/null

echo "127.0.0.1
localhost
$ServerName
*.$" | sudo tee /etc/opendkim/TrustedHosts > /dev/null

sudo opendkim-genkey -b 2048 -s $DKIMSelector -d $ServerName -D /etc/opendkim/keys/

echo "$DKIMSelector._key.$ServerName $ServerName:$DKIMSelector:/etc/opendkim/keys/$DKIMSelector.private" | sudo tee /etc/opendkim/KeyTable > /dev/null
echo "*@$ServerName $DKIMSelector._key.$ServerName" | sudo tee /etc/opendkim/SigningTable > /dev/null

# Ajuste de permissões e propriedade após a criação das chaves
sudo chmod 600 /etc/opendkim/keys/*
sudo chown opendkim:opendkim /etc/opendkim/keys/*

sudo chmod -R 777 /etc/opendkim/ && sudo chown -R opendkim:opendkim /etc/opendkim/
sudo cp /etc/opendkim/keys/$DKIMSelector.txt /root/dkim.txt && sudo chmod -R 777 /root/dkim.txt

DKIMFileCode=$(cat /root/dkim.txt)

echo '#!/usr/bin/node

const DKIM = `'$DKIMFileCode'`
console.log(DKIM.replace(/(\r\n|\n|\r|\t|"|\)| )/gm, "").split(";").find((c) => c.match("p=")).replace("p=",""))

'| sudo tee /root/dkimcode.sh > /dev/null

sudo chmod 777 /root/dkimcode.sh

echo "==================================================================== DKIM ==============================================================================="

echo "==================================================== POSTFIX ===================================================="

sleep 3

# Atualiza a lista de pacotes
sudo apt-get update

# Instala o Postfix e pacotes adicionais
sudo DEBIAN_FRONTEND=noninteractive apt-get install --assume-yes postfix postfix-policyd-spf-python opendmarc

debconf-set-selections <<< "postfix postfix/mailname string '"$ServerName"'"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
debconf-set-selections <<< "postfix postfix/destinations string '"$ServerName", localhost'"
sudo apt install postfix-policyd-spf-python -y
sudo apt-get install --assume-yes postfix

# Reconfigura o Postfix para aplicar as configurações
sudo DEBIAN_FRONTEND=noninteractive dpkg-reconfigure postfix

echo -e "$ServerName OK" | sudo tee /etc/postfix/access.recipients > /dev/null

echo -e "myhostname = $ServerName
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no
append_dot_my = no
readme_directory = no
compatibility_level = 2

# DKIM Settings
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:9982
non_smtpd_milters = inet:localhost:9982

# SPF Settings
policy-spf_time_limit = 3600s
smtpd_recipient_restrictions = 
  permit_mynetworks,
  permit_sasl_authenticated,
  reject_unauth_destination,
  check_policy_service unix:private/policyd-spf

# TLS parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/$ServerName/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/$ServerName/privkey.pem
smtpd_tls_security_level = may
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_ciphers = medium
smtpd_tls_exclude_ciphers = aNULL, MD5
smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
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
  permit_mynetworks,
  reject_invalid_helo_hostname,
  reject_non_fqdn_helo_hostname,
  permit

smtpd_sender_restrictions =
  permit_mynetworks,
  reject_non_fqdn_sender,
  reject_unknown_sender_,
  permit

smtpd_client_restrictions = 
  permit_mynetworks,
  reject_rbl_client zen.spamhaus.org,
  reject_rbl_client bl.spamcop.net,
  reject_unknown_client_hostname,
  permit

smtpd_data_restrictions = 
  reject_unauth_pipelining" | sudo tee /etc/postfix/main.cf > /dev/null
  
# Criação do arquivo de configuração do policyd-spf
sudo tee /etc/postfix-policyd-spf-python/policyd-spf.conf > /dev/null <<EOF
HELO_reject = False
Mail_From_reject = False
Rcpt_To_reject = True
EOF

# Criar o diretório necessário para o OpenDMARC
sudo mkdir -p /run/opendmarc

# Ajustar as permissões e a propriedade do diretório
sudo chown opendmarc:opendmarc /run/opendmarc
sudo chmod 750 /run/opendmarc

# Configuração do OpenDMARC
sudo tee /etc/opendmarc.conf > /dev/null <<EOF
Syslog true
Socket inet:54321@localhost
PidFile /run/opendmarc/opendmarc.pid
EOF

# Atualiza os arquivos de configuração do systemd
sudo systemctl daemon-reload

# Reinicia os serviços
sudo systemctl restart postfix
sudo systemctl restart opendkim
sudo systemctl restart opendmarc

# Verifica o status dos serviços
sudo systemctl status postfix
sudo systemctl status opendkim
sudo systemctl status opendmarc
echo "==================================================== POSTFIX ===================================================="

echo "==================================================== CLOUDFLARE ===================================================="

DKIMCode=$(/root/dkimcode.sh)

sleep 5

echo "  -- Obtendo Zona"
CloudflareZoneID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$&status=active" \
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
     --data '{ "type": "TXT", "name": "_dmarc.'$ServerName'", "content": "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmark@'$ServerName'; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r", "ttl": 120, "proxied": false }'

echo "  -- Cadastrando DKIM"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "'$DKIMSelector'._key.'$ServerName'", "content": "v=DKIM1; h=sha256; k=rsa; p='$DKIMCode'", "ttl": 120, "proxied": false }'

echo "  -- Cadastrando MX"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "MX", "name": "'$ServerName'", "content": "'$ServerName'", "ttl": 120, "priority": 10, "proxied": false }'

echo "==================================================== CLOUDFLARE ===================================================="

echo "==================================================== APPLICATION ===================================================="

echo '{
  "name": "sender",
  "version": "1.0.0",
  "dependencies": {
    "body-parser": "^1.20.1",
    "express": "^4.18.2",
    "html-to-text": "^8.2.1",
    "nodemailer": "^6.8.0"
  }
}' | sudo tee /root/package.json > /dev/null

echo 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0
const express = require("express")
const nodemailer = require("nodemailer")
const bodyparser = require("body-parser")
const { convert } = require("html-to-text")
const app = express()
app.use(bodyparser.json())
app.post("/email-manager/tmt/sendmail", async (req,res) => {
  let { to, fromName, fromUser, subject, html, attachments } = req.body
  let toAddress = to.shift()
  const transport = nodemailer.createTransport({
    port: 25,
    tls:{
      rejectUnauthorized: false
    }
  })
  html = html.replace(/(\r\n|\n|\r|\t)/gm, "")
  html = html.replace(/\s+/g, " ") 
  let message = {
    encoding: "base64",
    from: {
      name: fromName,
      address: `${fromUser}@'$ServerName'`
    },
    to: {
      name: fromName,
      address: toAddress
    },
    bcc: to,
    subject,
    attachments,
    html,
    list: {
      unsubscribe: [{
        url: "https://" + "'$ServerName'?action=unsubscribe&u=" + to,
        comment: "Cancelar Inscrição"
      }],
    },
    text: convert(html, { wordwrap: 85 })
  }
  if(attachments) message = { ...message, attachments }
  const sendmail = await transport.sendMail(message)
  return res.status(200).json(sendmail)
})
app.listen(4235)'  | tee /root/server.js > /dev/null

cd /root && npm install && pm2 start server.js && pm2 startup && pm2 save

npm install axios dotenv events

echo "==================================================== APPLICATION ===================================================="

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

# Reiniciar servidor
echo "Reiniciando o servidor em 5 segundos..."
sleep 5
sudo reboot
