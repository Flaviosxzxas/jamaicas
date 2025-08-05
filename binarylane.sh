#!/bin/bash

# ============================================
#  Verificação de permissão de root
# ============================================
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# INSERÇÃO AQUI Verificação e instalação do PHP
echo "Verificando se o PHP está instalado..."

if ! command -v php >/dev/null 2>&1; then
    echo "PHP não encontrado. Instalando php8.1-cli..."
    apt-get update
    apt-get install -y php8.1-cli
else
    echo "PHP já está instalado: $(php -v | head -n 1)"
fi
# ============================================
#  Atualização dos pacotes do sistema
# ============================================

echo "Atualizando pacotes..."
apt-get update
apt-get -y upgrade \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" \
  || {
    echo "Erro ao atualizar os pacotes."
    exit 1
  }

# ============================================
#  Definir variáveis principais
# ============================================
ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

# Verificar argumentos
if [ -z "$ServerName" ] || [ -z "$CloudflareAPI" ] || [ -z "$CloudflareEmail" ]; then
  echo "Erro: Argumentos insuficientes fornecidos."
  echo "Uso: $0 <ServerName> <CloudflareAPI> <CloudflareEmail>"
  exit 1
fi

# Validar ServerName
if [[ ! "$ServerName" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
  echo "Erro: ServerName inválido. Use algo como sub.example.com"
  exit 1
fi

# ============================================
#  Variáveis derivadas
# ============================================
Domain=$(echo "$ServerName" | awk -F. '{print $(NF-1)"."$NF}')
DKIMSelector=$(echo "$ServerName" | awk -F[.:] '{print $1}')

if [ -z "$Domain" ] || [ -z "$DKIMSelector" ]; then
  echo "Erro: Não foi possível calcular o Domain ou DKIMSelector. Verifique o ServerName."
  exit 1
fi

# Obter IP público
ServerIP=$(wget -qO- http://ip-api.com/line?fields=query)
if [ -z "$ServerIP" ]; then
  echo "Erro: Não foi possível obter o IP público."
  exit 1
fi

# ============================================
#  Depuração inicial
# ============================================
echo "===== DEPURAÇÃO ====="
echo "ServerName: $ServerName"
echo "CloudflareAPI: $CloudflareAPI"
echo "CloudflareEmail: $CloudflareEmail"
echo "Domain: $Domain"
echo "DKIMSelector: $DKIMSelector"
echo "ServerIP: $ServerIP"
echo "======================"

sleep 10

echo "==================================================================== Hostname && SSL ===================================================================="

# ============================================
#  Instalar pacotes básicos
# ============================================
apt-get install -y wget curl jq python3-certbot-dns-cloudflare openssl

# ============================================
#  Configurar Node.js
# ============================================
echo "Configurando Node.js..."
curl -fsSL https://deb.nodesource.com/setup_21.x | bash - \
    && apt-get install -y nodejs \
    && echo "Node.js instalado com sucesso: versão $(node -v)" || {
        echo "Alerta: Erro ao instalar o Node.js."
    }

echo "Verificando NPM..."
npm -v || {
    echo "Alerta: NPM não está instalado corretamente."
}

echo "Instalando PM2..."
npm install -g pm2 && echo "PM2 instalado: versão $(pm2 -v)" || {
    echo "Alerta: Falha na primeira tentativa de instalar o PM2. Testando alternativas..."

    npm cache clean --force
    npm install -g pm2 && echo "PM2 instalado na segunda tentativa!" || {
        echo "Alerta: Segunda tentativa falhou. Tentando via tarball..."

        npm install -g https://registry.npmjs.org/pm2/-/pm2-5.3.0.tgz && echo "PM2 instalado via tarball!" || {
            echo "Erro crítico: Não foi possível instalar o PM2."
        }
    }
}

mkdir -p /root/.secrets && chmod 0700 /root/.secrets/ && touch /root/.secrets/cloudflare.cfg && chmod 0400 /root/.secrets/cloudflare.cfg

echo "dns_cloudflare_email = $CloudflareEmail
dns_cloudflare_api_key = $CloudflareAPI" > /root/.secrets/cloudflare.cfg

echo -e "127.0.0.1 localhost
127.0.0.1 $ServerName
$ServerIP $ServerName" > /etc/hosts

echo -e "$ServerName" > /etc/hostname

hostnamectl set-hostname "$ServerName"

certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
  --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.cfg \
  --dns-cloudflare-propagation-seconds 60 --rsa-key-size 4096 -d "$ServerName"

wait

# ============================================
#  Corrigir SyntaxWarning em cloudflare.py
# ============================================
echo "Corrigindo SyntaxWarning no cloudflare.py..."
sed -i "s/self.email is ''/self.email == ''/g" /usr/lib/python3/dist-packages/CloudFlare/cloudflare.py
sed -i "s/self.token is ''/self.token == ''/g" /usr/lib/python3/dist-packages/CloudFlare/cloudflare.py
sed -i "s/self.certtoken is None/self.certtoken == None/g" /usr/lib/python3/dist-packages/CloudFlare/cloudflare.py

echo "Correção aplicada com sucesso em cloudflare.py."

echo "==================================================================== DKIM ==============================================================================="


# ============================================
#  Instalar OpenDKIM
# ============================================
apt-get install -y opendkim opendkim-tools
wait

# Criação dos diretórios
mkdir -p /etc/opendkim && mkdir -p /etc/opendkim/keys

# Permissões e propriedade
chown -R opendkim:opendkim /etc/opendkim/
chmod -R 750 /etc/opendkim/

# /etc/default/opendkim
cat <<EOF > /etc/default/opendkim
RUNDIR=/run/opendkim
SOCKET="inet:12301@127.0.0.1"
USER=opendkim
GROUP=opendkim
PIDFILE=\$RUNDIR/\$NAME.pid
EOF

# /etc/opendkim.conf
cat <<EOF > /etc/opendkim.conf
AutoRestart             Yes
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
Socket                  inet:12301@127.0.0.1
RequireSafeKeys         false
EOF

# /etc/opendkim/TrustedHosts
cat <<EOF > /etc/opendkim/TrustedHosts
127.0.0.1
localhost
$ServerName
*.$Domain
EOF

# Gerar chaves DKIM
opendkim-genkey -b 2048 -s mail -d "$ServerName" -D /etc/opendkim/keys/
chown opendkim:opendkim /etc/opendkim/keys/mail.private
chmod 640 /etc/opendkim/keys/mail.private

# KeyTable e SigningTable
echo "mail._domainkey.${ServerName} ${ServerName}:mail:/etc/opendkim/keys/mail.private" > /etc/opendkim/KeyTable
echo "*@${ServerName} mail._domainkey.${ServerName}" > /etc/opendkim/SigningTable

chmod -R 750 /etc/opendkim/

# Script para processar a chave DKIM
DKIMFileCode=$(cat /etc/opendkim/keys/mail.txt)
cat <<EOF > /root/dkimcode.sh
#!/usr/bin/node

const DKIM = \`$DKIMFileCode\`;
console.log(
  DKIM.replace(/(\\r\\n|\\n|\\r|\\t|"|\\)| )/gm, "")
  .split(";")
  .find((c) => c.match("p="))
  .replace("p=","")
);
EOF

chmod 755 /root/dkimcode.sh

echo "==================================================== POSTFIX ===================================================="

sleep 3

# ============================================
#  Atualização de pacotes
# ============================================
apt-get update
apt-get upgrade -y

# Desativar config automática do opendmarc
echo "dbconfig-common dbconfig-common/dbconfig-install boolean false" | debconf-set-selections
echo "opendmarc opendmarc/dbconfig-install boolean false" | debconf-set-selections

# Instalar dependências
echo "Instalando python3-pip e dnspython..."
apt-get install -y python3-pip
pip3 install dnspython

if [ $? -eq 0 ]; then
  echo "python3-pip e dnspython instalados com sucesso!"
else
  echo "Erro ao instalar python3-pip ou dnspython."
  exit 1
fi

# ============================================
# Instalar dependências para gerar PDF protegido
# ============================================
echo "Instalando wkhtmltopdf, pdfkit e PyPDF2 para PDF protegido..."
apt-get install -y wkhtmltopdf
pip3 install pdfkit PyPDF2

if [ $? -eq 0 ]; then
    echo "Dependências de PDF instaladas com sucesso!"
else
    echo "Erro ao instalar dependências de PDF (wkhtmltopdf, pdfkit, PyPDF2)."
    exit 1
fi

# ============================================
#  Funções para corrigir permissões
# ============================================
fix_makedefs_symlink() {
    local target_file="/usr/share/postfix/makedefs.out"
    local symlink="/etc/postfix/makedefs.out"

    if [ ! -L "$symlink" ]; then
        echo "Criando symlink de $target_file para $symlink..."
        ln -sf "$target_file" "$symlink"
    fi
}

fix_makedefs_permissions() {
    local target_file="/usr/share/postfix/makedefs.out"
    local symlink="/etc/postfix/makedefs.out"

    echo "Ajustando permissões do arquivo $target_file..."
    if [ -f "$target_file" ]; then
        chmod 644 "$target_file" || { echo "Erro ao ajustar permissões de $target_file."; exit 1; }
        chown root:root "$target_file" || { echo "Erro ao ajustar dono de $target_file."; exit 1; }
    fi

    if [ -L "$symlink" ]; then
        chmod 644 "$symlink" || { echo "Erro ao ajustar permissões do symlink $symlink."; exit 1; }
        chown root:root "$symlink" || { echo "Erro ao ajustar dono do symlink $symlink."; exit 1; }
    fi
}

# Instalar Postfix e outros
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix opendmarc pflogsumm
wait

fix_makedefs_symlink
fix_makedefs_permissions

# Configurações básicas do Postfix
debconf-set-selections <<< "postfix postfix/mailname string '$ServerName'"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
debconf-set-selections <<< "postfix postfix/destinations string 'localhost'"

echo -e "$ServerName OK" > /etc/postfix/access.recipients
postmap /etc/postfix/access.recipients

# ============================================
#  Criar e configurar header_checks
# ============================================
create_header_checks() {
    echo '/^[Rr]eceived: by .+? \(Postfix, from userid 0\)/ IGNORE' > /etc/postfix/header_checks

    # Converter para formato Unix usando dos2unix
    echo "Convertendo /etc/postfix/header_checks para formato Unix..."
    dos2unix /etc/postfix/header_checks

    echo "Conteúdo do arquivo /etc/postfix/header_checks:"
    cat -A /etc/postfix/header_checks

    postconf -e "header_checks = regexp:/etc/postfix/header_checks"
}

install_dos2unix() {
    if ! command -v dos2unix &> /dev/null; then
        echo "dos2unix não encontrado. Instalando..."
        apt-get update
        apt-get install -y dos2unix
        if [ $? -ne 0 ]; then
            echo "Erro ao instalar dos2unix."
            exit 1
        fi
    fi
}

main_header_checks() {
    install_dos2unix
    create_header_checks

    echo "Verificando erros específicos..."
    # Caso precise de algo adicional aqui
}

# Criar diretório para autenticação do Postfix
echo "Criando /var/spool/postfix/private..."
mkdir -p /var/spool/postfix/private
chown postfix:postfix /var/spool/postfix/private
chmod 700 /var/spool/postfix/private

# Verificar se o arquivo de autenticação existe
if [ ! -f /var/spool/postfix/private/auth ]; then
  echo "Criando arquivo de autenticação..."
  touch /var/spool/postfix/private/auth
  chown postfix:postfix /var/spool/postfix/private/auth
  chmod 660 /var/spool/postfix/private/auth
else
  echo "Arquivo de autenticação já existe."
fi

main_header_checks

# /etc/postfix/main.cf
cat <<EOF > /etc/postfix/main.cf
myhostname = $ServerName
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no
readme_directory = no
compatibility_level = 3.6

header_checks = regexp:/etc/postfix/header_checks
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases

# DKIM Settings
milter_protocol = 6
milter_default_action = accept
smtpd_milters = inet:127.0.0.1:54321, inet:127.0.0.1:12301
non_smtpd_milters = inet:127.0.0.1:54321, inet:127.0.0.1:12301

# Restrições de destinatários
smtpd_recipient_restrictions = 
    permit_mynetworks,
    check_recipient_access hash:/etc/postfix/access.recipients,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_unknown_recipient_domain,
    check_policy_service inet:127.0.0.1:10045

smtpd_client_connection_rate_limit = 100
smtpd_client_connection_count_limit = 50
anvil_rate_time_unit = 60s

message_size_limit = 10485760
default_destination_concurrency_limit = 50
maximal_queue_lifetime = 3d
bounce_queue_lifetime = 3d
smtp_destination_rate_delay = 1s

smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname, reject_unknown_helo_hostname

# TLS
smtpd_tls_cert_file=/etc/letsencrypt/live/$ServerName/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/$ServerName/privkey.pem
smtpd_tls_security_level = may
smtpd_tls_loglevel = 2
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, 3DES

smtp_tls_security_level = may
smtp_tls_loglevel = 2
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_ciphers = high
smtp_tls_exclude_ciphers = aNULL, MD5, 3DES

smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous, noplaintext
smtpd_sasl_tls_security_options = noanonymous
smtpd_tls_auth_only = yes

myorigin = localhost
mydestination = localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = loopback-only
inet_protocols = ipv4
EOF

# Salvar variáveis antes de instalar dependências
ORIGINAL_VARS=$(declare -p ServerName CloudflareAPI CloudflareEmail Domain DKIMSelector ServerIP)

# ============================================
#  Instalar e usar cpanminus para módulos Perl
# ============================================
# Dependências de compilação e Perl extras
apt-get install -y build-essential make gcc libssl-dev libperl-dev \
    libnet-dns-perl libio-multiplex-perl libnet-server-perl wget unzip libidn2-0-dev cpanminus

export PERL_MM_USE_DEFAULT=1
export PERL_AUTOINSTALL=--defaultdeps

# Verificar e instalar módulos Perl via cpanminus
check_and_install_perl_module() {
    local module_name=$1
    if perl -M"$module_name" -e '1' 2>/dev/null; then
        echo "Módulo Perl $module_name já instalado."
    else
        echo "Módulo Perl $module_name não encontrado. Instalando..."
        cpanm --notest "$module_name" || { echo "Erro ao instalar $module_name via cpanminus."; exit 1; }
    fi
}

perl_modules=("Net::Server::Daemonize" "Net::Server::Multiplex" "Net::Server::PreFork" "Net::DNS" "IO::Multiplex")
for module in "${perl_modules[@]}"; do
    check_and_install_perl_module "$module"
done

# ============================================
#  Instalar Postfwd
# ============================================
if [ ! -d "/opt/postfwd" ]; then
    echo "Baixando e instalando o Postfwd..."
    cd /tmp || { echo "Erro ao acessar /tmp."; exit 1; }
    wget https://github.com/postfwd/postfwd/archive/master.zip || { echo "Erro ao baixar o Postfwd."; exit 1; }
    unzip master.zip || { echo "Erro ao descompactar o Postfwd."; exit 1; }
    mv postfwd-master /opt/postfwd || { echo "Erro ao mover o Postfwd."; exit 1; }
    echo "Postfwd instalado com sucesso."
else
    echo "Pasta /opt/postfwd já existe, assumindo Postfwd instalado."
fi

eval "$ORIGINAL_VARS"

# ============================================
#  Criar conf do Postfwd
# ============================================
mkdir -p /opt/postfwd/etc
if [ ! -f "/opt/postfwd/etc/postfwd.cf" ]; then
    cat <<EOF > /opt/postfwd/etc/postfwd.cf
#######################################################
# Regras de Controle de Limites por Servidor
#######################################################
# KingHost
id=limit-kinghost
pattern=recipient mx=.*kinghost.net
action=rate(global/300/3600) defer_if_permit "Limite de 300 e-mails por hora atingido para KingHost."

# UOL Host
id=limit-uolhost
pattern=recipient mx=.*uhserver
action=rate(global/300/3600) defer_if_permit "Limite de 300 e-mails por hora atingido para UOL Host."

# LocaWeb
id=limit-locaweb
pattern=recipient mx=.*locaweb.com.br
action=rate(global/500/3600) defer_if_permit "Limite de 500 e-mails por hora atingido para LocaWeb."

# Yahoo
id=limit-yahoo
pattern=recipient mx=.*yahoo.com
action=rate(global/150/3600) defer_if_permit "Limite de 150 e-mails por hora atingido para Yahoo."

# Mandic
id=limit-mandic
pattern=recipient mx=.*mandic.com.br
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Mandic."

# Titan
id=limit-titan
pattern=recipient mx=.*titan.email
action=rate(global/500/3600) defer_if_permit "Limite de 500 e-mails por hora atingido para Titan."

# Google
id=limit-google
pattern=recipient mx=.*google
action=rate(global/2000/3600) defer_if_permit "Limite de 2000 e-mails por hora atingido para Google."

# Hotmail
id=limit-hotmail
pattern=recipient mx=.*hotmail.com
action=rate(global/1000/86400) defer_if_permit "Limite de 1000 e-mails por dia atingido para Hotmail."

# Office 365
id=limit-office365
pattern=recipient mx=.*outlook.com
action=rate(global/2000/3600) defer_if_permit "Limite de 2000 e-mails por hora atingido para Office 365."

# Secureserver (GoDaddy)
id=limit-secureserver
pattern=recipient mx=.*secureserver.net
action=rate(global/300/3600) defer_if_permit "Limite de 300 e-mails por hora atingido para GoDaddy."

# Zimbra
id=limit-zimbra
pattern=recipient mx=.*zimbra
action=rate(global/400/3600) defer_if_permit "Limite de 400 e-mails por hora atingido para Zimbra."

# Argentina: Fibertel
id=limit-fibertel
pattern=recipient mx=.*fibertel.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Fibertel."

# Speedy
id=limit-speedy
pattern=recipient mx=.*speedy.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Speedy."

# Personal (Arnet)
id=limit-personal
pattern=recipient mx=.*personal.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Personal Arnet."

# Telecom
id=limit-telecom
pattern=recipient mx=.*telecom.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Telecom."

# Claro
id=limit-claro
pattern=recipient mx=.*claro.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Claro."

# México: Telmex
id=limit-telmex
pattern=recipient mx=.*prodigy.net.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Telmex."

# Axtel
id=limit-axtel
pattern=recipient mx=.*axtel.net
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Axtel."

# Izzi
id=limit-izzi
pattern=recipient mx=.*izzi.net.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Izzi Telecom."

# Megacable
id=limit-megacable
pattern=recipient mx=.*megacable.com.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Megacable."

# TotalPlay
id=limit-totalplay
pattern=recipient mx=.*totalplay.net.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para TotalPlay."

# Telcel
id=limit-telcel
pattern=recipient mx=.*telcel.net
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Telcel."

# Outros (sem limite)
id=no-limit
pattern=recipient mx=.*
action=permit
EOF
else
    echo "Arquivo /opt/postfwd/etc/postfwd.cf já existe, pulando."
fi

# ============================================
#  Script de inicialização do Postfwd
# ============================================
mkdir -p /opt/postfwd/bin
cat <<'EOF' > /opt/postfwd/bin/postfwd-script.sh
#!/bin/sh
#
# Startscript for the postfwd daemon

PATH=/bin:/usr/bin:/usr/local/bin

PFWCMD=/opt/postfwd/sbin/postfwd3
PFWCFG=/opt/postfwd/etc/postfwd.cf
PFWPID=/var/tmp/postfwd3-master.pid

PFWUSER=postfix
PFWGROUP=postfix
PFWINET=127.0.0.1
PFWPORT=10045

PFWARG="--shortlog --summary=600 --cache=600 --cache-rbl-timeout=3600 --cleanup-requests=1200 --cleanup-rbls=1800 --cleanup-rates=1200"

P1="`basename ${PFWCMD}`"
case "$1" in
 start*)
   [ /var/tmp/postfwd3-master.pid ] && rm -Rf /var/tmp/postfwd3-master.pid
   echo "Starting ${P1}..."
   ${PFWCMD} ${PFWARG} --daemon --file=${PFWCFG} --interface=${PFWINET} --port=${PFWPORT} --user=${PFWUSER} --group=${PFWGROUP} --pidfile=${PFWPID}
   ;;

 debug*)
   echo "Starting ${P1} in debug mode..."
   ${PFWCMD} ${PFWARG} -vv --daemon --file=${PFWCFG} --interface=${PFWINET} --port=${PFWPORT} --user=${PFWUSER} --group=${PFWGROUP} --pidfile=${PFWPID}
   ;;

 stop*)
   ${PFWCMD} --interface=${PFWINET} --port=${PFWPORT} --pidfile=${PFWPID} --kill
   ;;

 reload*)
   ${PFWCMD} --interface=${PFWINET} --port=${PFWPORT} --pidfile=${PFWPID} -- reload
   ;;

 restart*)
   $0 stop
   sleep 4
   $0 start
   ;;

 *)
   echo "Unknown argument \"$1\"" >&2
   echo "Usage: `basename $0` {start|stop|debug|reload|restart}"
   exit 1
   ;;
esac
exit $?
EOF

chmod +x /opt/postfwd/bin/postfwd-script.sh
ln -sf /opt/postfwd/bin/postfwd-script.sh /etc/init.d/postfwd

# Reiniciar serviços
echo "Iniciando o Postfwd..."
/etc/init.d/postfwd start || { echo "Erro ao iniciar o Postfwd."; exit 1; }
echo "Reiniciando o Postfix..."
systemctl restart postfix || { echo "Erro ao reiniciar Postfix."; exit 1; }

echo "==================================================== OpenDMARC ===================================================="

# ============================================
#  Criar diretórios OpenDMARC
# ============================================
echo "[OpenDMARC] Criando diretórios..."
mkdir -p /run/opendmarc /etc/opendmarc /var/log/opendmarc /var/lib/opendmarc
chown opendmarc:opendmarc /run/opendmarc /etc/opendmarc /var/log/opendmarc /var/lib/opendmarc
chmod 750 /run/opendmarc /etc/opendmarc /var/log/opendmarc /var/lib/opendmarc

# /etc/opendmarc.conf
preencher_opendmarc_conf() {
    local opendmarc_conf="/etc/opendmarc.conf"

    if [[ ! -f "$opendmarc_conf" ]]; then
        echo "[OpenDMARC] Criando $opendmarc_conf..."
        touch "$opendmarc_conf"
    fi

    local configuracoes=(
        "Syslog true"
        "Socket inet:54321@127.0.0.1"
        "PidFile /run/opendmarc/opendmarc.pid"
        "AuthservID OpenDMARC"
        "IgnoreHosts /etc/opendmarc/ignore.hosts"
        "RejectFailures false"
        "TrustedAuthservIDs ${ServerName}"
        "HistoryFile /var/lib/opendmarc/opendmarc.dat"
    )

    echo "[OpenDMARC] Preenchendo $opendmarc_conf..."
    for cfg in "${configuracoes[@]}"; do
        if ! grep -q "^${cfg//\//\\/}" "$opendmarc_conf"; then
            echo "$cfg" >> "$opendmarc_conf"
        fi
    done

    chown opendmarc:opendmarc "$opendmarc_conf"
    chmod 644 "$opendmarc_conf"
}

preencher_opendmarc_conf

# /etc/opendmarc/ignore.hosts
touch /etc/opendmarc/ignore.hosts
if ! grep -q "127.0.0.1" /etc/opendmarc/ignore.hosts; then
    echo "127.0.0.1" >> /etc/opendmarc/ignore.hosts
fi
if ! grep -q "::1" /etc/opendmarc/ignore.hosts; then
    echo "::1" >> /etc/opendmarc/ignore.hosts
fi
chown opendmarc:opendmarc /etc/opendmarc/ignore.hosts
chmod 644 /etc/opendmarc/ignore.hosts

# Arquivo de histórico
touch /var/lib/opendmarc/opendmarc.dat
chown opendmarc:opendmarc /var/lib/opendmarc/opendmarc.dat
chmod 644 /var/lib/opendmarc/opendmarc.dat

rm -f /run/opendmarc/opendmarc.pid

echo "[OpenDMARC] Reiniciando OpenDKIM..."
systemctl restart opendkim
if systemctl is-active --quiet opendkim; then
    echo "[OpenDMARC] OpenDKIM reiniciado com sucesso."
else
    echo "[OpenDMARC] Falha ao reiniciar OpenDKIM."
fi

echo "[OpenDMARC] Reiniciando OpenDMARC..."
systemctl restart opendmarc
if systemctl is-active --quiet opendmarc; then
    echo "[OpenDMARC] OpenDMARC reiniciado com sucesso."
else
    echo "[OpenDMARC] Falha ao reiniciar OpenDMARC."
fi

echo "[Postfix] Ajustando dependência systemd..."
systemctl edit postfix <<EOF
[Unit]
After=opendmarc.service
Requires=opendmarc.service
EOF

systemctl daemon-reload
systemctl restart postfix

echo "==================================================== CLOUDFLARE ===================================================="

echo "===== DEPURAÇÃO: ANTES DE CONFIGURAÇÃO CLOUDFLARE ====="
echo "ServerName: $ServerName"
echo "CloudflareAPI: $CloudflareAPI"
echo "CloudflareEmail: $CloudflareEmail"
echo "Domain: $Domain"
echo "DKIMSelector: $DKIMSelector"
echo "ServerIP: $ServerIP"

# Instalar jq (caso não exista)
if ! command -v jq &> /dev/null; then
  apt-get update
  apt-get install -y jq
fi

DKIMCode=$(/root/dkimcode.sh)
sleep 5

echo "===== DEPURAÇÃO: ANTES DE OBTER ZONA CLOUDFLARE ====="
echo "DKIMCode: $DKIMCode"
echo "Domain: $Domain"
echo "ServerName: $ServerName"

# Obter ID da zona
CloudflareZoneID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$Domain&status=active" \
  -H "X-Auth-Email: $CloudflareEmail" \
  -H "X-Auth-Key: $CloudflareAPI" \
  -H "Content-Type: application/json" | jq -r '.result[0].id')

if [ -z "$CloudflareZoneID" ] || [ "$CloudflareZoneID" = "null" ]; then
  echo "Erro: Não foi possível obter o ID da zona do Cloudflare."
  exit 1
fi

echo "===== DEPURAÇÃO: APÓS OBTER ZONA CLOUDFLARE ====="
echo "CloudflareZoneID: $CloudflareZoneID"

# Função para obter detalhes de registro
get_record_details() {
  local record_name=$1
  local record_type=$2
  curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records?name=$record_name&type=$record_type" \
    -H "X-Auth-Email: $CloudflareEmail" \
    -H "X-Auth-Key: $CloudflareAPI" \
    -H "Content-Type: application/json"
}

# Função para criar ou atualizar registros no Cloudflare
create_or_update_record() {
  local record_name=$1
  local record_type=$2
  local record_content=$3
  local record_ttl=120
  local record_priority=$4
  local record_proxied=false

  echo "===== DEPURAÇÃO: ANTES DE OBTER DETALHES DO REGISTRO ====="
  echo "RecordName: $record_name"
  echo "RecordType: $record_type"

  # Detalhes do registro existente
  local response
  response=$(get_record_details "$record_name" "$record_type")

  local existing_id
  existing_id=$(echo "$response" | jq -r '.result[0].id')
  local existing_content
  existing_content=$(echo "$response" | jq -r '.result[0].content')
  local existing_ttl
  existing_ttl=$(echo "$response" | jq -r '.result[0].ttl')
  local existing_priority
  existing_priority=$(echo "$response" | jq -r '.result[0].priority')

  echo "===== DEPURAÇÃO: DETALHES DO REGISTRO EXISTENTE ====="
  echo "ExistingID: $existing_id"
  echo "ExistingContent: $existing_content"
  echo "ExistingTTL: $existing_ttl"
  echo "ExistingPriority: $existing_priority"

  # Montar JSON
  local data
  if [ "$record_type" == "MX" ]; then
    data=$(jq -n \
      --arg type "$record_type" \
      --arg name "$record_name" \
      --arg content "$record_content" \
      --arg ttl "$record_ttl" \
      --argjson proxied "$record_proxied" \
      --arg priority "$record_priority" \
      '{type: $type, name: $name, content: $content, ttl: ($ttl|tonumber), proxied: $proxied, priority: ($priority|tonumber)}'
    )
  else
    data=$(jq -n \
      --arg type "$record_type" \
      --arg name "$record_name" \
      --arg content "$record_content" \
      --arg ttl "$record_ttl" \
      --argjson proxied "$record_proxied" \
      '{type: $type, name: $name, content: $content, ttl: ($ttl|tonumber), proxied: $proxied}'
    )
  fi

  # Se registro não existe, criar via POST
  if [ "$existing_id" = "null" ] || [ -z "$existing_id" ]; then
    echo "  -- Criando novo registro ($record_type) para $record_name..."
    response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
      -H "X-Auth-Email: $CloudflareEmail" \
      -H "X-Auth-Key: $CloudflareAPI" \
      -H "Content-Type: application/json" \
      --data "$data")
    echo "$response"
  else
    # Se já existe, fazer PUT (update)
    echo "  -- Atualizando registro ($record_type) para $record_name [ID: $existing_id]..."
    response=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records/$existing_id" \
      -H "X-Auth-Email: $CloudflareEmail" \
      -H "X-Auth-Key: $CloudflareAPI" \
      -H "Content-Type: application/json" \
      --data "$data")
    echo "$response"
  fi
}

# Criar/atualizar registros
echo "  -- Configurando registros DNS Cloudflare..."

# Garante que o DKIMCode fique em uma única linha sem aspas que atrapalhem
DKIMCode=$(echo "$DKIMCode" | tr -d '\n' | tr -s ' ')
EscapedDKIMCode=$(printf '%s' "$DKIMCode" | sed 's/\"/\\\"/g')

create_or_update_record "$DKIMSelector" "A" "$ServerIP" ""
create_or_update_record "$ServerName" "TXT" "\"v=spf1 a:$ServerName -all\"" ""
create_or_update_record "_dmarc.$ServerName" "TXT" "\"v=DMARC1; p=reject; rua=mailto:dmarc-reports@$ServerName; ruf=mailto:dmarc-reports@$ServerName; sp=reject; adkim=s; aspf=s\"" ""
create_or_update_record "mail._domainkey.$ServerName" "TXT" "\"v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode\"" ""
create_or_update_record "$ServerName" "MX" "$ServerName" "10"

echo "==================================================== APPLICATION ===================================================="

# Instalar Apache, PHP e módulos
DEBIAN_FRONTEND=noninteractive apt-get -y install apache2 php php-cli php-dev php-curl php-gd libapache2-mod-php php-mbstring

# Verificar se /var/www/html existe
if [ ! -d "/var/www/html" ]; then
    echo "Pasta /var/www/html não existe."
    exit 1
fi

rm -f /var/www/html/index.html

cat <<EOF > /var/www/html/index.php
<?php
header('HTTP/1.0 403 Forbidden');
http_response_code(401);
exit();
?>
EOF

# -----------------------------------------------------------
# AQUI CRIAMOS O unsubscribe.php COM O CÓDIGO PARA DESCADASTRO
# -----------------------------------------------------------
cat <<'EOF' > /var/www/html/unsubscribe.php
<?php
/**
 * unsubscribe.php
 *
 * Exemplo de script que lida com descadastramentos de lista de e-mails
 * via GET e POST (One-Click Unsubscribe).
 */

// Caminho do arquivo onde salvaremos os e-mails descadastrados
$unsubFile = __DIR__ . '/unsubscribed_emails.txt';

/**
 * Função simples para processar e-mail e salvar (exemplo).
 * Em produção, você poderia remover o e-mail de um BD ou
 * marcar em sua plataforma de mailing.
 */
function unsubscribeEmail($email, $unsubFile) {
    // Filtra o e-mail para evitar problemas básicos de segurança/formatação
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);

    // Verifica se ainda parece um e-mail válido
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false; // E-mail inválido
    }

    // Neste exemplo, apenas registramos num arquivo de texto
    file_put_contents($unsubFile, $email . PHP_EOL, FILE_APPEND | LOCK_EX);
    return true;
}

// Detecta se estamos em POST (One-Click) ou GET (clique manual)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['email'])) {
        $email = $_POST['email'];
        $ok = unsubscribeEmail($email, $unsubFile);
        if ($ok) {
            echo "OK: E-mail '{$email}' removido via POST.";
        } else {
            echo "ERRO: E-mail inválido ou problema ao processar (POST).";
        }
    } else {
        echo "ERRO: Parâmetro 'email' não encontrado no POST.";
    }
} else {
    // GET (clique manual no link unsubscribe.php?email=...)
    if (!empty($_GET['email'])) {
        $email = $_GET['email'];
        $ok = unsubscribeEmail($email, $unsubFile);
        if ($ok) {
            echo "OK: E-mail '{$email}' removido via GET.";
        } else {
            echo "ERRO: E-mail inválido ou problema ao processar (GET).";
        }
    } else {
        echo "ERRO: Parâmetro 'email' não encontrado no GET.";
    }
}
?>
EOF

# Criar arquivo de registro e ajustar permissões
touch /var/www/html/unsubscribed_emails.txt
chown www-data:www-data /var/www/html/unsubscribed_emails.txt
chmod 664 /var/www/html/unsubscribed_emails.txt

# Reiniciar Apache para aplicar essas mudanças mínimas
systemctl restart apache2

# ============================================
#  Habilitar SSL no Apache e redirecionamento
# ============================================
echo "Habilitando SSL e Rewrite no Apache..."
a2enmod ssl
a2enmod rewrite

# Cria o VirtualHost para forçar HTTPS
cat <<EOF > "/etc/apache2/sites-available/ssl-$ServerName.conf"
<VirtualHost *:80>
    ServerName $ServerName
    DocumentRoot /var/www/html

    # Redireciona todo HTTP para HTTPS
    RewriteEngine On
    RewriteCond %{SERVER_NAME} =$ServerName
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName $ServerName
    DocumentRoot /var/www/html

    SSLEngine on

    SSLCertificateFile /etc/letsencrypt/live/$ServerName/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/$ServerName/privkey.pem
    # Opcional: aproveita config SSL da Let's Encrypt
    # Se existir /etc/letsencrypt/options-ssl-apache.conf
    # descomente a linha abaixo:
    #Include /etc/letsencrypt/options-ssl-apache.conf

    <Directory /var/www/html>
       AllowOverride All
       Require all granted
    </Directory>
</VirtualHost>
</IfModule>
EOF

# Habilita o novo VirtualHost e recarrega
a2ensite "ssl-$ServerName"
systemctl reload apache2

echo "==================================================== APPLICATION ===================================================="

# ============================================
#  CRIAR E DESCARTAR noreply@$ServerName, unsubscribe@$ServerName, contato@$ServerName
# ============================================
echo "Configurando noreply@$ServerName, unsubscribe@$ServerName e contacto@$ServerName..."

# Ajusta apenas para um valor explícito, sem $virtual_alias_maps
postconf -e "virtual_alias_domains = $ServerName"
postconf -e "virtual_alias_maps = hash:/etc/postfix/virtual"
postconf -e "local_recipient_maps="

if [ ! -f /etc/postfix/virtual ]; then
    touch /etc/postfix/virtual
fi

# noreply
if ! grep -q "noreply@$ServerName" /etc/postfix/virtual; then
  echo "noreply@$ServerName   noreply" >> /etc/postfix/virtual
fi

# unsubscribe
if ! grep -q "unsubscribe@$ServerName" /etc/postfix/virtual; then
  echo "unsubscribe@$ServerName   unsubscribe" >> /etc/postfix/virtual
fi

# contacto
if ! grep -q "contacto@$ServerName" /etc/postfix/virtual; then
  echo "contacto@$ServerName   contacto" >> /etc/postfix/virtual
fi

postmap /etc/postfix/virtual

# Descartar local "noreply", "unsubscribe" e "contacto"
if ! grep -q "^noreply:" /etc/aliases; then
  echo "noreply: /dev/null" >> /etc/aliases
fi

if ! grep -q "^unsubscribe:" /etc/aliases; then
  echo "unsubscribe: /dev/null" >> /etc/aliases
fi

if ! grep -q "^contacto:" /etc/aliases; then
  echo "contacto: /dev/null" >> /etc/aliases
fi

newaliases
systemctl reload postfix
echo "Feito! Agora noreply@$ServerName, unsubscribe@$ServerName e contacto@$ServerName existem e são descartados (sem erro)."

echo "================================= Todos os comandos foram executados com sucesso! ==================================="

echo "======================================================= FIM =========================================================="

echo "================================================= Reiniciar servidor ================================================="

# Se necessário reboot
if [ -f /var/run/reboot-required ]; then
  echo "Reiniciando o servidor em 5 segundos devido a atualizações críticas..."
  sleep 5
  reboot
else
  echo "Reboot não necessário. Aguardando 5 segundos antes de finalizar..."
  sleep 5
fi

echo "Finalizando o script."
exit 0
