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
wait # adiciona essa linha para esperar que o comando seja concluído

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

# Permitir tráfego na porta 25
sudo ufw allow 25/tcp
sudo ufw allow 10031/tcp


# Instalar pacotes básicos
sudo -i apt-get install wget curl jq python3-certbot-dns-cloudflare -y

# Configurar NodeSource e instalar Node.js
echo "Configurando Node.js..."
curl -fsSL https://deb.nodesource.com/setup_21.x | sudo bash - \
    && sudo apt-get install -y nodejs \
    && echo "Node.js instalado com sucesso: versão $(node -v)" || {
        echo "Alerta: Erro ao instalar o Node.js. Continuando sem ele, mas verifique o log e tente novamente."
    }

# Verificar a versão do npm
echo "Verificando NPM..."
npm -v || {
    echo "Alerta: NPM não está instalado corretamente. Continuando, mas algumas funcionalidades podem falhar."
}

# Instalar PM2
echo "Instalando PM2..."
npm install -g pm2 && echo "PM2 instalado com sucesso: versão $(pm2 -v)" || {
    echo "Alerta: Falha na primeira tentativa de instalar o PM2. Testando alternativas..."
    
    # Tentativa alternativa 1: limpar cache do NPM e reinstalar
    npm cache clean --force
    npm install -g pm2 && echo "PM2 instalado com sucesso na segunda tentativa!" || {
        echo "Alerta: Segunda tentativa de instalar o PM2 falhou. Tentando com tarball..."
        
        # Tentativa alternativa 2: instalar PM2 via tarball
        npm install -g https://registry.npmjs.org/pm2/-/pm2-5.3.0.tgz && echo "PM2 instalado via tarball com sucesso!" || {
            echo "Erro crítico: Não foi possível instalar o PM2. Continuando o script, mas PM2 não estará disponível."
        }
    }
}

sudo mkdir -p /root/.secrets && sudo chmod 0700 /root/.secrets/ && sudo touch /root/.secrets/cloudflare.cfg && sudo chmod 0400 /root/.secrets/cloudflare.cfg

echo "dns_cloudflare_email = $CloudflareEmail
dns_cloudflare_api_key = $CloudflareAPI" | sudo tee /root/.secrets/cloudflare.cfg > /dev/null

echo -e "127.0.0.1 localhost
127.0.0.1 $ServerName
$ServerIP $ServerName" | sudo tee /etc/hosts > /dev/null

echo -e "$ServerName" | sudo tee /etc/hostname > /dev/null

sudo hostnamectl set-hostname "$ServerName"

certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.cfg --dns-cloudflare-propagation-seconds 60 --rsa-key-size 4096 -d $ServerName
wait # adiciona essa linha para esperar que o comando seja concluído

# Corrigir o SyntaxWarning no cloudflare.py
echo "Corrigindo SyntaxWarning no cloudflare.py..."

sed -i "s/self.email is ''/self.email == ''/g" /usr/lib/python3/dist-packages/CloudFlare/cloudflare.py
sed -i "s/self.token is ''/self.token == ''/g" /usr/lib/python3/dist-packages/CloudFlare/cloudflare.py
sed -i "s/self.certtoken is None/self.certtoken == None/g" /usr/lib/python3/dist-packages/CloudFlare/cloudflare.py

echo "Correção aplicada com sucesso no arquivo cloudflare.py."

echo "==================================================================== Hostname && SSL ===================================================================="

echo "==================================================================== DKIM ==============================================================================="

# Instalação dos pacotes necessários
sudo apt-get install opendkim opendkim-tools -y
wait # adiciona essa linha para esperar que o comando seja concluído

# Criação dos diretórios necessários
sudo mkdir -p /etc/opendkim && sudo mkdir -p /etc/opendkim/keys

# Configuração de permissões e propriedade
sudo chown -R opendkim:opendkim /etc/opendkim/
sudo chmod -R 750 /etc/opendkim/

# Configuração do arquivo default do OpenDKIM
echo "RUNDIR=/run/opendkim
SOCKET=\"inet:12301@localhost\"
USER=opendkim
GROUP=opendkim
PIDFILE=\$RUNDIR/\$NAME.pid
EXTRAAFTER=" | sudo tee /etc/default/opendkim > /dev/null

# Configuração do arquivo de configuração do OpenDKIM
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
Domain                  ${ServerName}
KeyFile                 /etc/opendkim/keys/mail.private
Selector                mail
Socket                  inet:12301@localhost
RequireSafeKeys         false" | sudo tee /etc/opendkim.conf > /dev/null

# Definição dos hosts confiáveis para o DKIM
echo "127.0.0.1
localhost
$ServerName
*.$Domain" | sudo tee /etc/opendkim/TrustedHosts > /dev/null

# Geração das chaves DKIM
sudo opendkim-genkey -b 2048 -s mail -d $ServerName -D /etc/opendkim/keys/
wait # adiciona essa linha para esperar que o comando seja concluído

# Alterar permissões do arquivo de chave DKIM
sudo chown opendkim:opendkim /etc/opendkim/keys/mail.private
sudo chmod 640 /etc/opendkim/keys/mail.private

# Configuração da KeyTable e SigningTable
echo "mail._domainkey.${ServerName} ${ServerName}:mail:/etc/opendkim/keys/mail.private" | sudo tee /etc/opendkim/KeyTable > /dev/null
echo "*@${ServerName} mail._domainkey.${ServerName}" | sudo tee /etc/opendkim/SigningTable > /dev/null

# Ajuste de permissões e propriedade das chaves
sudo chmod -R 750 /etc/opendkim/

# Código para processar a chave DKIM
DKIMFileCode=$(cat /etc/opendkim/keys/mail.txt)

echo '#!/usr/bin/node

const DKIM = `'$DKIMFileCode'`
console.log(DKIM.replace(/(\r\n|\n|\r|\t|"|\)| )/gm, "").split(";").find((c) => c.match("p=")).replace("p=",""))

' | sudo tee /root/dkimcode.sh > /dev/null

sudo chmod 755 /root/dkimcode.sh

echo "==================================================================== DKIM =============================================================================="


echo "==================================================== POSTFIX ===================================================="

sleep 3

# Atualiza a lista de pacotes
sudo apt-get update
wait # adiciona essa linha para esperar que o comando seja concluído

# Desativa a configuração automática do banco de dados do opendmarc
echo "dbconfig-common dbconfig-common/dbconfig-install boolean false" | sudo debconf-set-selections
echo "opendmarc opendmarc/dbconfig-install boolean false" | sudo debconf-set-selections

# Atualizando pacotes
sudo apt update
sudo apt upgrade -y

# Instalar dependências para policyd-spf
echo "Instalando python3-pip e dnspython..."
sudo apt install -y python3-pip
pip3 install dnspython

if [ $? -eq 0 ]; then
  echo "python3-pip e dnspython instalados com sucesso!"
else
  echo "Erro ao instalar python3-pip ou dnspython. Verifique os logs."
  exit 1
fi

# Instalar Postfix e outros pacotes necessários
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y postfix postfix-policyd-spf-python opendmarc pflogsumm
wait # adiciona essa linha para esperar que o comando seja concluído

# Garantir que policyd-spf seja executável
sudo chmod +x /usr/bin/policyd-spf

# Configurações básicas do Postfix
debconf-set-selections <<< "postfix postfix/mailname string '"$ServerName"'"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
debconf-set-selections <<< "postfix postfix/destinations string '"$ServerName", localhost'"

# Define o intervalo de portas a serem testadas
START_PORT=10031
END_PORT=10100

# Função para verificar se a porta está em uso
is_port_in_use() {
    ss -tuln | grep -q ":$1"
    return $?
}

# Encontra uma porta livre
find_free_port() {
    for ((port=$START_PORT; port<=$END_PORT; port++)); do
        if ! is_port_in_use $port; then
            echo $port
            return 0
        fi
    done
    echo "Nenhuma porta livre encontrada no intervalo $START_PORT-$END_PORT" >&2
    exit 1
}

# Encontra uma porta livre
FREE_PORT=$(find_free_port)

echo "Porta livre encontrada: $FREE_PORT"

# Configura o serviço postfix-policyd-spf-python com a porta encontrada
echo "Configurando postfix-policyd-spf-python com a porta $FREE_PORT..."
sudo tee /etc/systemd/system/postfix-policyd-spf-python.service > /dev/null <<EOF
[Unit]
Description=Postfix Policyd SPF Python
After=network.target

[Service]
ExecStart=/usr/bin/policyd-spf --inet=127.0.0.1:$FREE_PORT
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

# Recarrega o systemd e reinicia o serviço
sudo systemctl daemon-reload
sudo systemctl enable postfix-policyd-spf-python
sudo systemctl restart postfix-policyd-spf-python

# Verifica se o serviço está ativo
if sudo systemctl is-active --quiet postfix-policyd-spf-python; then
    echo "Serviço postfix-policyd-spf-python configurado e ativo na porta $FREE_PORT."
else
    echo "Erro: Serviço postfix-policyd-spf-python não conseguiu iniciar na porta $FREE_PORT."
    exit 1
fi

# Configura o Postfix para usar a porta encontrada
echo "Configurando Postfix para usar a porta $FREE_PORT..."
sudo sed -i "s|check_policy_service inet:127.0.0.1:[0-9]*|check_policy_service inet:127.0.0.1:$FREE_PORT|" /etc/postfix/main.cf
sudo systemctl restart postfix

echo "Configuração concluída. Postfix e postfix-policyd-spf-python estão configurados para usar a porta $FREE_PORT."

# Próximas configurações...
echo "Executando próximas configurações..."

# Adicionar configuração para policyd-spf no master.cf
sudo tee -a /etc/postfix/master.cf > /dev/null <<EOF
policyd-spf  unix  -       n       n       -       0       spawn
    user=nobody argv=/usr/bin/policyd-spf

policy-spf unix - n n - - spawn
  user=nobody argv=/usr/bin/python3 /usr/share/postfix-policyd-spf-python/policyd-spf.py
EOF

# Atualiza o arquivo /etc/postfix/main.cf para usar a nova porta
echo "Atualizando o arquivo /etc/postfix/main.cf..."

# Remove a linha existente de check_policy_service (se existir)
sudo sed -i '/check_policy_service inet:127.0.0.1:[0-9]*/d' /etc/postfix/main.cf

# Adiciona a nova linha com a porta dinâmica
sudo sed -i "/smtpd_recipient_restrictions =/a\    check_policy_service inet:127.0.0.1:$FREE_PORT" /etc/postfix/main.cf

# Reinicia o Postfix para aplicar as alterações
echo "Reiniciando o Postfix..."
sudo systemctl restart postfix


# Instala o pacote postfix, que é o servidor de e-mail
sudo apt-get install --assume-yes postfix
wait # adiciona essa linha para esperar que o comando seja concluído

# Atualiza o arquivo access.recipients
echo -e "$ServerName OK" | sudo tee /etc/postfix/access.recipients > /dev/null
sudo postmap /etc/postfix/access.recipients

# Função para criar e configurar o arquivo header_checks
create_header_checks() {
    # Crie o arquivo de verificação de cabeçalhos
    echo '/^[Rr]eceived: by .+? \(Postfix, from userid 0\)/ IGNORE' | sudo tee /etc/postfix/header_checks > /dev/null

    # Converta o arquivo para o formato Unix usando dos2unix
    echo "Converting file /etc/postfix/header_checks to Unix format..."
    sudo dos2unix /etc/postfix/header_checks

    # Verifique o conteúdo do arquivo
    echo "Conteúdo do arquivo /etc/postfix/header_checks:"
    cat -A /etc/postfix/header_checks

    # Atualize a configuração do Postfix para usar o novo arquivo
    sudo postconf -e "header_checks = regexp:/etc/postfix/header_checks"

    # Reinicie o Postfix
    echo "Reiniciando o Postfix..."
    sudo systemctl restart postfix
}

# Função para instalar o dos2unix se necessário
install_dos2unix() {
    if ! command -v dos2unix &> /dev/null; then
        echo "dos2unix não encontrado. Instalando..."
        sudo apt-get update
        sudo apt-get install -y dos2unix
        if [ $? -ne 0 ]; then
            echo "Erro ao instalar o dos2unix. Verifique o log de erros."
            exit 1
        fi
    fi
}

# Função principal
main() {
    # Instale o dos2unix se necessário
    install_dos2unix

    # Crie e configure o arquivo header_checks
    create_header_checks

    # Exiba mensagem de erro específica, se aplicável
    echo "Verificando erros específicos..."

    # Mensagem informativa
    echo "==================================================== POSTFIX ==================="
}

# Execute a função principal
main

echo -e "myhostname = $ServerName
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no
readme_directory = no
compatibility_level = 3

# Header checks
header_checks = regexp:/etc/postfix/header_checks

# Local recipient maps
# local_recipient_maps = proxy:unix:passwd.byname \$alias_maps

# DKIM Settings
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:12301
non_smtpd_milters = inet:localhost:12301

# Login without Username and Password
policy-spf_time_limit = 3600
smtpd_recipient_restrictions =
  permit_mynetworks,
  check_recipient_access hash:/etc/postfix/access.recipients,
  permit_sasl_authenticated,
  reject_unauth_destination,
  check_policy_service inet:127.0.0.1:10031


# Limites de conexão para proteção e controle de envio
smtpd_client_connection_rate_limit = 5
smtpd_client_connection_count_limit = 10
anvil_rate_time_unit = 60s

# Configurações para lidar com erros temporários e definitivos no Postfix
# smtpd_error_sleep_time = 5
#   Define o tempo de espera (em segundos) após um erro para evitar sobrecarga do servidor.
# smtpd_soft_error_limit = 10
#   Define o número máximo de erros temporários (4xx) permitidos antes de encerrar a conexão.
# smtpd_hard_error_limit = 20
#   Define o número máximo de erros definitivos (5xx) permitidos antes de encerrar a conexão.

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

myorigin = /etc/mailname
mydestination = $ServerName, $Domain, localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all" | sudo tee /etc/postfix/main.cf > /dev/null

# Certifica-se de que o diretório para o policyd-spf existe
sudo mkdir -p /etc/postfix-policyd-spf-python

# Configura o arquivo policyd-spf.conf
sudo tee /etc/postfix-policyd-spf-python/policyd-spf.conf > /dev/null <<EOF
HELO_reject = False
Mail_From_reject = False
PermError_reject = False
TempError_Defer = False
inet = 127.0.0.1:10031
EOF


# Adiciona regras de controle de limites
echo "#######################################################
# Regras de Controle de Limites por Servidor
#######################################################

# KingHost
id=limit-kinghost
pattern=recipient mx=.*kinghost.net
action=rate(global/100/3600) defer_if_permit \"Limite de 100 e-mails por hora atingido para KingHost.\"

# UOL Host
id=limit-uolhost
pattern=recipient mx=.*uhserver
action=rate(global/100/3600) defer_if_permit \"Limite de 100 e-mails por hora atingido para UOL Host.\"

# LocaWeb
id=limit-locaweb
pattern=recipient mx=.*locaweb.com.br
action=rate(global/150/3600) defer_if_permit \"Limite de 150 e-mails por hora atingido para LocaWeb.\"

# Mandic
id=limit-mandic
pattern=recipient mx=.*mandic.com.br
action=rate(global/100/3600) defer_if_permit \"Limite de 100 e-mails por hora atingido para Mandic.\"

# Titan
id=limit-titan
pattern=recipient mx=.*titan.email
action=rate(global/150/3600) defer_if_permit \"Limite de 150 e-mails por hora atingido para Titan.\"

# Google
id=limit-google
pattern=recipient mx=.*google
action=rate(global/200/3600) defer_if_permit \"Limite de 200 e-mails por hora atingido para Google.\"

# Outlook
id=limit-outlook
pattern=recipient mx=.*outlook
action=rate(global/150/3600) defer_if_permit \"Limite de 150 e-mails por hora atingido para Outlook.\"

# Secureserver (GoDaddy)
id=limit-secureserver
pattern=recipient mx=.*secureserver.net
action=rate(global/100/3600) defer_if_permit \"Limite de 100 e-mails por hora atingido para GoDaddy.\"

# Zimbra
id=limit-zimbra
pattern=recipient mx=.*zimbra
action=rate(global/120/3600) defer_if_permit \"Limite de 120 e-mails por hora atingido para Zimbra.\"

# Provedores na Argentina
# Fibertel
id=limit-fibertel
pattern=recipient mx=.*fibertel.com.ar
action=rate(global/100/3600) defer_if_permit \"Limite de 100 e-mails por hora atingido para Fibertel.\"

# Speedy
id=limit-speedy
pattern=recipient mx=.*speedy.com.ar
action=rate(global/100/3600) defer_if_permit \"Limite de 100 e-mails por hora atingido para Speedy.\"

# Provedores no México
# Telmex
id=limit-telmex
pattern=recipient mx=.*prodigy.net.mx
action=rate(global/100/3600) defer_if_permit \"Limite de 100 e-mails por hora atingido para Telmex.\"

# Axtel
id=limit-axtel
pattern=recipient mx=.*axtel.net
action=rate(global/100/3600) defer_if_permit \"Limite de 100 e-mails por hora atingido para Axtel.\"

# Outros (Sem Limite)
id=no-limit
pattern=recipient
action=permit
" | sudo tee /etc/postfix-policyd.conf > /dev/null


echo "==================================================== POSTFIX ===================================================="

echo "==================================================== OpenDMARC ===================================================="

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
wait # adiciona essa linha para esperar que o comando seja concluído

# Configurar e reiniciar o OpenDKIM
sudo systemctl restart opendkim
wait # adiciona essa linha para esperar que o comando seja concluído

# Configurar e reiniciar o OpenDMARC
sudo systemctl restart opendmarc
wait # adiciona essa linha para esperar que o comando seja concluído

echo "==================================================== OpenDMARC ===================================================="

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
     --data '{ "type": "TXT", "name": "_dmarc.'$ServerName'", "content": "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmark@'$ServerName'; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r", "ttl": 120, "proxied": false }'

echo "  -- Cadastrando DKIM"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "TXT", "name": "mail._domainkey.'$ServerName'", "content": "v=DKIM1; h=sha256; k=rsa; p='$DKIMCode'", "ttl": 120, "proxied": false }'

echo "  -- Cadastrando MX"
curl -s -o /dev/null -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
     -H "X-Auth-Email: $CloudflareEmail" \
     -H "X-Auth-Key: $CloudflareAPI" \
     -H "Content-Type: application/json" \
     --data '{ "type": "MX", "name": "'$ServerName'", "content": "'$ServerName'", "ttl": 120, "priority": 10, "proxied": false }'

echo "==================================================== CLOUDFLARE ===================================================="

echo "==================================================== APPLICATION ===================================================="

# Instala Apache, PHP e módulos necessários
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install apache2 php php-cli php-dev php-curl php-gd libapache2-mod-php --assume-yes
wait # adiciona essa linha para esperar que o comando seja concluído

# Verifica a existência do diretório /var/www/html
if [ ! -d "/var/www/html" ]; then
    echo "Folder /var/www/html does not exist"
    exit 1
fi

# Remove o arquivo index.html se existir
sudo rm -f /var/www/html/index.html

# Adiciona o código PHP ao arquivo index.php
echo "<?php
header('HTTP/1.0 403 Forbidden');
http_response_code(401);
exit();
?>" | sudo tee /var/www/html/index.php > /dev/null

# Instala a extensão php-mbstring
sudo apt-get install php-mbstring -y

# Reinicia o serviço Apache
sudo /etc/init.d/apache2 restart

echo "==================================================== APPLICATION ===================================================="

echo "================================= Todos os comandos foram executados com sucesso! ==================================="

echo "======================================================= FIM =========================================================="

# Reiniciar servidor
echo "Reiniciando o servidor em 5 segundos..."
sleep 5
sudo reboot
