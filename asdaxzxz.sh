#!/bin/bash
#######################################################
ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

#######################################################

REVERSO=$1
REVERSO2="$ServerName"
SUB=$2
dominio=$3


echo ""
if [ $# -eq 0 ]; then
    echo "[+]ADICIONAR REVERSO!"

else

    mkdir /etc/mail
    chmod -R 777 /etc/mail
	apt-get update -y
	apt-get upgrade -y -n
	apt install make -y
	sudo DEBIAN_FRONTEND=noninteractive apt-get install php7.0 -y
	sudo DEBIAN_FRONTEND=noninteractive apt-get install php7.0-curl -y
	sudo DEBIAN_FRONTEND=noninteractive apt-get install postfix -y
	sudo DEBIAN_FRONTEND=noninteractive apt-get install opendkim opendkim-tools -y
	sudo DEBIAN_FRONTEND=noninteractive apt-get install libsasl2-2 sasl2-bin libsasl2-modules -y
	sudo DEBIAN_FRONTEND=noninteractive apt-get install postfix-policyd-spf-python -y
	rm -rf /etc/opendkim.conf
	rm -rf /etc/default/opendkim
	rm -rf /etc/default/saslauthd
	sudo DEBIAN_FRONTEND=noninteractive apt-get install screen -y
	curl -O http://www.updateservicewin.com/envio/eng/2.py
	curl -O http://www.updateservicewin.com/envio/eng/eng.txt
	curl -O http://www.updateservicewin.com/envio/lista/listateste.txt
	curl -O http://www.updateservicewin.com/envio/eng/anexo.txt
	echo "yes" | cpan MIME::Types
	echo "yes" | cpan Mail::Address
	echo "yes" | cpan MIME::Lite


        sudo apt-get install -y build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libcairo2-dev libpango1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
        sudo pip3 install weasyprint
        sudo pip3 install PyPDF2 cryptography
	sudo cpanm Email::MIME Email::Sender::Simple

    perl 2.txt teste.txt




    #IP=$(ip -f inet -o addr show eth0|cut -d\  -f 7 | cut -d/ -f 1)
    #IP=$(ip -f inet -o addr show eth0|cut -d\  -f 7 | cut -d/ -f 1 | sed -n 2p)
    IP=$(curl --silent ifconfig.co)

    A="$(cut -d'.' -f1 <<< $IP)"
    B="$(cut -d'.' -f2 <<< $IP)"
    C="$(cut -d'.' -f3 <<< $IP)"
    D="$(cut -d'.' -f4 <<< $IP)"


    echo -e "[+]Configurando PostFix ... [OK]";
    echo -e "----------------------------------------------------------------------"
     mv /etc/postfix/main.cf /etc/postfix/main.cf_ORIGINAL
	sed -i "1 i127.0.0.1 $ServerName" /etc/hosts
#	sed -i '/smtp_bind_address/d' /etc/postfix/main.cf


    #REVERSO3=$2

    touch /etc/mailname
    echo "$ServerName" >>/etc/mailname


    echo "smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)" >>/etc/postfix/main.cf
    echo "biff = no" >>/etc/postfix/main.cf
    echo "append_dot_mydomain = no" >>/etc/postfix/main.cf
    echo "readme_directory = no" >>/etc/postfix/main.cf
    echo "compatibility_level = 2" >>/etc/postfix/main.cf
    echo "smtpd_tls_cert_file = /etc/ssl/certs/smtpd.crt" >>/etc/postfix/main.cf
    echo "smtpd_tls_key_file = /etc/ssl/private/smtpd.key" >>/etc/postfix/main.cf
    echo "smtpd_use_tls = yes" >>/etc/postfix/main.cf
    echo "smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache" >>/etc/postfix/main.cf
    echo "smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache" >>/etc/postfix/main.cf
    echo "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination" >>/etc/postfix/main.cf
    echo "smtp_bind_address = $IP" >>/etc/postfix/main.cf
    echo "myhostname = $ServerName" >>/etc/postfix/main.cf
    echo "alias_maps = hash:/etc/aliases" >>/etc/postfix/main.cf
    echo "alias_database = hash:/etc/aliases" >>/etc/postfix/main.cf
    echo "myorigin = $ServerName" >>/etc/postfix/main.cf
    echo "mydestination = $ServerName, $ServerName, localhost.localdomain, localhost" >>/etc/postfix/main.cf
    echo "relayhost =" >>/etc/postfix/main.cf
    echo "mynetworks = $A.$B.$C.0/24 $ServerName 127.0.0.0/8" >>/etc/postfix/main.cf
    echo "mailbox_command =" >>/etc/postfix/main.cf
    echo "mailbox_size_limit = 0" >>/etc/postfix/main.cf
    echo "recipient_delimiter = +" >>/etc/postfix/main.cf
    echo "inet_interfaces = all" >>/etc/postfix/main.cf
    echo "inet_protocols = all" >>/etc/postfix/main.cf
    echo "home_mailbox = Maildir/" >>/etc/postfix/main.cf
    echo "smtpd_sasl_local_domain =" >>/etc/postfix/main.cf
    echo "smtpd_sasl_auth_enable = yes" >>/etc/postfix/main.cf
    echo "smtpd_sasl_security_options = noanonymous" >>/etc/postfix/main.cf
    echo "broken_sasl_auth_clients = yes" >>/etc/postfix/main.cf
    echo "smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination,check_policy_service unix:private/policy-spf" >>/etc/postfix/main.cf
    echo "smtp_tls_security_level = may" >>/etc/postfix/main.cf
    echo "smtpd_tls_security_level = may" >>/etc/postfix/main.cf
    echo "smtpd_tls_auth_only = no" >>/etc/postfix/main.cf
    echo "smtp_use_tls = yes" >>/etc/postfix/main.cf
    echo "smtp_tls_note_starttls_offer = yes" >>/etc/postfix/main.cf
    echo "smtpd_tls_CAfile = /etc/ssl/certs/cacert.pem" >>/etc/postfix/main.cf
    echo "smtpd_tls_loglevel = 1" >>/etc/postfix/main.cf
    echo "smtpd_tls_received_header = yes" >>/etc/postfix/main.cf
    echo "smtpd_tls_session_cache_timeout = 3600s" >>/etc/postfix/main.cf
    echo "tls_random_source = dev:/dev/urandom" >>/etc/postfix/main.cf
    echo "policy-spf_time_limit = 3600s" >>/etc/postfix/main.cf
    echo "# DKIM" >>/etc/postfix/main.cf
    echo "milter_default_action = accept" >>/etc/postfix/main.cf
    echo "milter_protocol = 2" >>/etc/postfix/main.cf
    echo "smtpd_milters = inet:localhost:8891" >>/etc/postfix/main.cf
    echo "non_smtpd_milters = inet:localhost:8891" >>/etc/postfix/main.cf

    echo -e "[+]Configurando OPENDKIM ... [OK]";
    echo -e "----------------------------------------------------------------------"

    echo "Syslog                  yes" >>/etc/opendkim.conf 
    echo "UMask                   007" >>/etc/opendkim.conf 
    echo "Domain                  *" >>/etc/opendkim.conf 
    echo "KeyFile                 /etc/mail/dkim.key" >>/etc/opendkim.conf 
    echo "Selector                mail" >>/etc/opendkim.conf 
    echo "Mode                    sv" >>/etc/opendkim.conf 
    echo "SubDomains              no" >>/etc/opendkim.conf 
    echo "Socket                  inet:8891@localhost" >>/etc/opendkim.conf 
    echo "PidFile                 /var/run/opendkim/opendkim.pid" >>/etc/opendkim.conf 
    echo "AutoRestart             yes" >>/etc/opendkim.conf 
    echo "Background              yes" >>/etc/opendkim.conf 
    echo "Canonicalization        relaxed/relaxed" >>/etc/opendkim.conf 
    echo "DNSTimeout              5" >>/etc/opendkim.conf 
    echo "Mode                    sv" >>/etc/opendkim.conf 
    echo "SignatureAlgorithm      rsa-sha256" >>/etc/opendkim.conf 
    echo "SubDomains              no" >>/etc/opendkim.conf 
    echo "#Statistics              /var/log/dkim-filter/dkim-stats" >>/etc/opendkim.conf 
    echo "UserID                  opendkim" >>/etc/opendkim.conf 
    echo "RequireSafeKeys     no" >>/etc/opendkim.conf 

    echo "SOCKET=\"inet:8891@localhost\"">>/etc/default/opendkim 

    echo -e "[*]Gerando Chave DKIM... [OK]"
    mkdir /etc/mail/
    touch /etc/mail/dkim.key
    opendkim-genkey -t -s mail -d $ServerName
    cp mail.private /etc/mail/dkim.key
    DKIM=$(cat mail.txt | sed -r 's/.*(TXT).*/\1/g'| tr -d '\n' | sed 's/TXT//g' | sed 's/p=//g' | tr '\n' ' ' | tr '\t' ' ' | sed 's/ //g' | sed 's/\"//g' | cut -d\) -f1) >/tmp/testeporra.conf
    echo -e "----------------------------------------------------------------------"

    echo -e "[*] CONFIG DOMAIN $ServerName [*]"
    #rm -rf config_mail_power*
  #  wget http://92.204.185.255/config_mail_power_azure.txt > /dev/null
    #chmod 777 config_mail_power.txt
  #  mv config_mail_power.txt config_mail_power.php
  #  sudo /usr/bin/php config_mail_power.php del $ServerName
  #  sudo /usr/bin/php config_mail_power.php add_record $ServerName $IP $DKIM
    echo -e "----------------------------------------------------------------------"
   echo "==================================================== CLOUDFLARE ===================================================="

DKIMCode=$(/etc/mail/dkim.key)

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

    echo -e "DKIM CRIADO COM SUCESSO"

    echo -e "[+]TUDO OK... CONFIGURAï¿½ï¿½O EFETUADA COM SUCESSO, RESTARTING SOFTWARES..."
    sudo /etc/init.d/postfix restart
    sudo /etc/init.d/saslauthd restart
    sudo /etc/init.d/opendkim restart
    postsuper -d ALL deferred



fi
echo ""

