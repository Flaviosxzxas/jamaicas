#!/bin/bash

ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

echo "Atualizando repositórios e instalando o jq..."
sudo apt-get update && sudo apt-get install -y jq

# Obter o endereço IPv4
ServerIP=$(wget -qO- http://ip-api.com/line\?fields=query)

# Obter o endereço IPv6
ServerIPv6=$(ip -6 addr show scope global | grep "inet6" | awk '{print $2}' | cut -d'/' -f1 | head -n 1)

Domain=$(echo $ServerName | cut -d "." -f2-)
DKIMSelector=$(echo $ServerName | awk -F[.:] '{print $1}')

echo "Configurando Servidor: $ServerName"

sleep 4

echo "==================================================== CLOUDFLARE 1 ===================================================="

echo "  -- Obtendo Zona"
CloudflareZoneID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$Domain&status=active" \
  -H "X-Auth-Email: $CloudflareEmail" \
  -H "X-Auth-Key: $CloudflareAPI" \
  -H "Content-Type: application/json" | jq -r '{"result"}[] | .[0] | .id')

# Cadastrando registro A
echo "  -- Cadastrando A"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "A", "name": "'$ServerName'", "content": "'$ServerIP'", "ttl": 60, "proxied": false }'

# Cadastrando registro AAAA
echo "  -- Cadastrando AAAA"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "AAAA", "name": "'$ServerName'", "content": "'$ServerIPv6'", "ttl": 60, "proxied": false }'
	 
echo "==================================================== CLOUDFLARE 1 ===================================================="

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

echo -e "::1 localhost
::1 $ServerName
$ServerIP $ServerName" | sudo tee /etc/hosts > /dev/null

echo -e "$ServerName" | sudo tee /etc/hostname > /dev/null

sudo hostnamectl set-hostname "$ServerName"

certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.cfg --dns-cloudflare-propagation-seconds 60 --rsa-key-size 4096 -d $ServerName

echo "==================================================================== Hostname && SSL ===================================================================="

echo "==================================================================== DKIM ==============================================================================="

sudo apt-get install opendkim opendkim-tools -y
sudo mkdir -p /etc/opendkim && sudo mkdir -p /etc/opendkim/keys
sudo chmod -R 777 /etc/opendkim/ && sudo chown -R opendkim:opendkim /etc/opendkim/

echo "RUNDIR=/run/opendkim
SOCKET="inet:9982@[::1]"
USER=opendkim
GROUP=opendkim
PIDFILE=\$RUNDIR/\$NAME.pid
EXTRAAFTER=" | sudo tee /etc/default/opendkim > /dev/null

echo "AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes
Canonicalization        relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                  opendkim:opendkim
Socket                  inet6:9982@[::1]
RequireSafeKeys false" | sudo tee /etc/opendkim.conf > /dev/null

echo "127.0.0.1
localhost
$ServerName
*.$Domain" | sudo tee /etc/opendkim/TrustedHosts > /dev/null

sudo opendkim-genkey -b 2048 -s $DKIMSelector -d $ServerName -D /etc/opendkim/keys/

echo "$DKIMSelector._domainkey.$ServerName $ServerName:$DKIMSelector:/etc/opendkim/keys/$DKIMSelector.private" | sudo tee /etc/opendkim/KeyTable > /dev/null
echo "*@$ServerName $DKIMSelector._domainkey.$ServerName" | sudo tee /etc/opendkim/SigningTable > /dev/null

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

debconf-set-selections <<< "postfix postfix/mailname string '"$ServerName"'"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
debconf-set-selections <<< "postfix postfix/destinations string '"$ServerName", localhost'"

sudo apt-get install --assume-yes postfix

echo -e "$ServerName OK" | sudo tee /etc/postfix/access.recipients > /dev/null

echo -e "myhostname = $ServerName
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2

# DKIM Settings
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet6:[::1]:9982
non_smtpd_milters = inet6:[::1]:9982

# Login without Username and Password
smtpd_recipient_restrictions =
  permit_mynetworks,
  check_recipient_access hash:/etc/postfix/access.recipients,
  permit_sasl_authenticated,
  reject_unauth_destination

# TLS parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/$ServerName/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/$ServerName/privkey.pem
smtpd_tls_security_level=may
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
inet_protocols = all" | sudo tee /etc/postfix/main.cf > /dev/null

sleep 3

service opendkim restart
service postfix restart

echo "==================================================== POSTFIX ===================================================="

echo "==================================================== CLOUDFLARE ===================================================="

DKIMCode=$(/root/dkimcode.sh)

sleep 5

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

# Adicionando um log no final
echo "Todos os comandos foram executados com sucesso!"
