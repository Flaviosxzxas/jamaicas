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

# Permitir tráfego na porta 25 e 587
sudo ufw allow 25/tcp
sudo ufw allow 587/tcp

# Instalar pacotes básicos
sudo apt-get install wget curl jq python3-certbot-dns-cloudflare openssl -y

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
sudo apt-get upgrade -y

# Desativa a configuração automática do banco de dados do opendmarc
echo "dbconfig-common dbconfig-common/dbconfig-install boolean false" | sudo debconf-set-selections
echo "opendmarc opendmarc/dbconfig-install boolean false" | sudo debconf-set-selections

# Instalar dependências para policyd-spf
echo "Instalando python3-pip e dnspython..."
sudo apt-get install -y python3-pip
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

# Atualizar o arquivo master.cf para configurar o policyd-spf
if ! grep -q "policy-spf" /etc/postfix/master.cf; then
    echo "Adicionando configuração para policyd-spf no master.cf..."
    sudo bash -c 'cat >> /etc/postfix/master.cf <<EOF
# SPF 
policy-spf unix - n n - - spawn
  user=nobody argv=/usr/bin/python3 /usr/bin/policyd-spf
EOF'
else
    echo "Configuração para policyd-spf já existe no master.cf, pulando esta etapa."
fi

# Verificar e adicionar a configuração da porta 587, se necessário
if ! grep -v '^#' /etc/postfix/master.cf | grep -q "submission inet n - n - - smtpd"; then
    echo "Adicionando configuração para a porta 587 no master.cf..."
    sudo bash -c 'cat >> /etc/postfix/master.cf <<EOF
# Porta 587 para envio de e-mails com STARTTLS
submission inet n - n - - smtpd
  -o smtpd_tls_security_level=encrypt
  -o smtpd_tls_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1
  -o smtpd_tls_ciphers=HIGH:!aNULL:!MD5:!3DES:!RC4:!eNULL
  -o smtpd_tls_exclude_ciphers=aNULL,MD5,3DES
  -o smtpd_tls_loglevel=1
  -o smtpd_tls_received_header=yes
  -o smtpd_tls_session_cache_timeout=3600s
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sender_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination
EOF'
else
    echo "Configuração para a porta 587 já existe no master.cf, pulando esta etapa."
fi

# Função para configurar aliases
echo "Removendo comentário e atualizando o arquivo de aliases"
# Remover o comentário caso exista
sudo sed -i '/^# See man 5 aliases for format/d' /etc/aliases

# Adicionar o alias
echo "contacto: contacto@$ServerName" | sudo tee -a /etc/aliases

# Atualizar aliases
sudo newaliases


# Configurações básicas do Postfix
debconf-set-selections <<< "postfix postfix/mailname string '"$ServerName"'"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
debconf-set-selections <<< "postfix postfix/destinations string '"$ServerName", localhost'"

# Configura o serviço postfix-policyd-spf-python com a porta encontrada
echo "Configurando postfix-policyd-spf-python"

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

# Instalar pacotes necessários para Dovecot (sem IMAP e POP3)
echo "Instalando pacotes do Dovecot..."
sudo apt-get install dovecot-core -y

# Iniciar e habilitar o serviço Dovecot
echo "Iniciando e habilitando o serviço Dovecot..."
sudo systemctl start dovecot
sudo systemctl enable dovecot

# Criar diretório necessário para a autenticação do Postfix
echo "Criando diretório /var/spool/postfix/private e ajustando permissões..."
sudo mkdir -p /var/spool/postfix/private
sudo chown postfix:postfix /var/spool/postfix/private
sudo chmod 700 /var/spool/postfix/private

# Verificar se o arquivo de autenticação existe e criar manualmente se necessário
echo "Verificando se o arquivo de autenticação existe..."
if [ ! -f /var/spool/postfix/private/auth ]; then
  echo "Criando arquivo de autenticação..."
  sudo touch /var/spool/postfix/private/auth
  sudo chown postfix:postfix /var/spool/postfix/private/auth
  sudo chmod 660 /var/spool/postfix/private/auth
else
  echo "Arquivo de autenticação já existe."
fi

# Configura o arquivo 10-auth.conf para habilitar SASL no Dovecot
echo "Configurando o arquivo 10-auth.conf para habilitar SASL..."
sudo tee /etc/dovecot/conf.d/10-auth.conf > /dev/null <<EOF
# /etc/dovecot/conf.d/10-auth.conf
disable_plaintext_auth = yes
auth_mechanisms = plain login

!include auth-system.conf.ext

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF

# Corrigir permissões no arquivo de autenticação
echo "Ajustando permissões para o arquivo de autenticação..."
sudo chown postfix:postfix /var/spool/postfix/private/auth
sudo chmod 660 /var/spool/postfix/private/auth

# Configura o arquivo 10-ssl.conf para usar certificados Let's Encrypt
echo "Configurando SSL/TLS no Dovecot..."
sudo tee /etc/dovecot/conf.d/10-ssl.conf > /dev/null <<EOF
##
## SSL settings
##

# Habilita suporte SSL/TLS
ssl = yes

# Caminhos para o certificado e a chave privada emitidos pelo Let's Encrypt
ssl_cert = </etc/letsencrypt/live/$ServerName/fullchain.pem
ssl_key = </etc/letsencrypt/live/$ServerName/privkey.pem

# Define o protocolo mínimo como TLSv1.2 para evitar o uso de protocolos inseguros
ssl_min_protocol = TLSv1.2

# Define as cifras seguras a serem usadas, excluindo cifras obsoletas
ssl_cipher_list = HIGH:!aNULL:!MD5:!3DES

# Prefere as cifras do servidor em vez das do cliente
ssl_prefer_server_ciphers = yes

# Caminho para os parâmetros DH
ssl_dh = </usr/share/dovecot/dh.pem

# Diretório de CAs confiáveis para validação de certificados de clientes, se necessário
ssl_client_ca_dir = /etc/ssl/certs

# Evita o uso de tickets de sessão SSL para maior segurança
ssl_options = no_ticket
EOF

# Gerar DH params se necessário
echo "Verificando e gerando DH params..."
if [ ! -f /usr/share/dovecot/dh.pem ]; then
  openssl dhparam -out /usr/share/dovecot/dh.pem 4096
fi

# Configuração adicional no arquivo principal de configuração do Dovecot
echo "Adicionando configuração SSL no arquivo principal de configuração do Dovecot..."
sudo tee -a /etc/dovecot/dovecot.conf > /dev/null <<EOF
# /etc/dovecot/dovecot.conf

# Incluindo o arquivo de configuração de SSL
!include conf.d/10-ssl.conf
EOF

# Configuração de logging no Dovecot
echo "Adicionando configurações de logging detalhado no 10-logging.conf..."
sudo tee /etc/dovecot/conf.d/10-logging.conf > /dev/null <<EOF
# /etc/dovecot/conf.d/10-logging.conf

# Caminhos de log
log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot-info.log
debug_log_path = /var/log/dovecot-debug.log

# Ativar logging detalhado
mail_debug = yes
auth_debug = yes
EOF

    # Mensagem informativa
    echo "==================================================== POSTFIX ===================================================="
}

# Execute a função principal
main

echo -e "myhostname = $ServerName
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no
readme_directory = no
compatibility_level = 3.6
#nis_domain_name =

# Header checks
header_checks = regexp:/etc/postfix/header_checks

# Local recipient maps
local_recipient_maps = proxy:unix:passwd.byname $alias_maps
alias_maps = hash:/etc/aliases

# DKIM Settings
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:12301
non_smtpd_milters = inet:localhost:12301

# Login without Username and Password
policy-spf_time_limit = 30
smtpd_recipient_restrictions = 
  permit_mynetworks,
  check_recipient_access hash:/etc/postfix/access.recipients,
  permit_sasl_authenticated,
  reject_unauth_destination,
  check_policy_service unix:policy-spf,
  reject_unknown_recipient_domain

# Limites de conexão
smtpd_client_connection_rate_limit = 100
smtpd_client_connection_count_limit = 50
anvil_rate_time_unit = 60s

# Gerenciamento de filas
message_size_limit = 10485760
default_destination_concurrency_limit = 50
maximal_queue_lifetime = 3d
bounce_queue_lifetime = 3d

# Retransmissão controlada
smtp_destination_rate_delay = 1s

# Configurações para lidar com erros temporários e definitivos no Postfix
# smtpd_error_sleep_time = 5
#   Define o tempo de espera (em segundos) após um erro para evitar sobrecarga do servidor.
# smtpd_soft_error_limit = 10
#   Define o número máximo de erros temporários (4xx) permitidos antes de encerrar a conexão.
# smtpd_hard_error_limit = 20
#   Define o número máximo de erros definitivos (5xx) permitidos antes de encerrar a conexão.

# Habilita a autenticação SASL para enviar e-mails. Necessário para autenticação segura.
smtpd_sasl_auth_enable = yes

# Define o método de autenticação SASL (aqui usamos Dovecot).
smtpd_sasl_type = dovecot

# Especifica o caminho para o serviço de autenticação do Dovecot.
smtpd_sasl_path = private/auth

# Define opções de segurança para autenticação SASL:
# - noanonymous: Não permite autenticação anônima.
# - noplaintext: Exige que as credenciais sejam transmitidas de forma segura.
smtpd_sasl_security_options = noanonymous, noplaintext

# Adiciona mais restrições de segurança no SASL quando TLS é usado.
smtpd_sasl_tls_security_options = noanonymous

# Força o uso de TLS para autenticação. Garantia de que os dados de login estão criptografados.
smtpd_tls_auth_only = yes

# Restrições para remetentes:
# - permite remetentes autenticados ou da rede confiável.
# - rejeita remetentes com domínio ou hostname inválido.
#  smtpd_sender_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_sender_login_mismatch, reject_unknown_reverse_client_hostname, reject_unknown_sender_domain

# Restrições para o comando HELO/EHLO:
# - valida o hostname enviado no comando.
# - rejeita conexões de servidores com hostname inválido, não qualificado (FQDN) ou desconhecido.
smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname, reject_unknown_helo_hostname


# TLS parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/$ServerName/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/$ServerName/privkey.pem
smtpd_tls_security_level = may
smtpd_tls_loglevel = 2
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_ciphers = HIGH:!aNULL:!MD5:!3DES:!RC4:!eNULL
smtpd_tls_exclude_ciphers = aNULL, MD5, 3DES

# Forçar TLS para conexões de saída
smtp_tls_security_level = may
smtp_tls_loglevel = 2
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_ciphers = high
smtp_tls_exclude_ciphers = aNULL, MD5, 3DES, RC4, eNULL

# SASL Authentication
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous, noplaintext
smtpd_sasl_tls_security_options = noanonymous
smtpd_tls_auth_only = yes

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
TempError_Defer = True
skip_addresses = 127.0.0.0/8,::ffff:127.0.0.0/104,::1
debugLevel = 10
EOF


# Adiciona regras de controle de limites
echo "#######################################################
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

# Outlook
id=limit-outlook
pattern=recipient mx=.*outlook
action=rate(global/1500/3600) defer_if_permit "Limite de 1500 e-mails por hora atingido para Outlook."

# Secureserver (GoDaddy)
id=limit-secureserver
pattern=recipient mx=.*secureserver.net
action=rate(global/300/3600) defer_if_permit "Limite de 300 e-mails por hora atingido para GoDaddy."

# Zimbra
id=limit-zimbra
pattern=recipient mx=.*zimbra
action=rate(global/400/3600) defer_if_permit "Limite de 400 e-mails por hora atingido para Zimbra."

# Provedores na Argentina
# Fibertel
id=limit-fibertel
pattern=recipient mx=.*fibertel.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Fibertel."

# Speedy
id=limit-speedy
pattern=recipient mx=.*speedy.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Speedy."

# Provedores no México
# Telmex
id=limit-telmex
pattern=recipient mx=.*prodigy.net.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Telmex."

# Axtel
id=limit-axtel
pattern=recipient mx=.*axtel.net
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Axtel."

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

# Configurar e reiniciar o OpenDKIM
sudo systemctl restart opendkim
wait # adiciona essa linha para esperar que o comando seja concluído

# Configurar e reiniciar o OpenDMARC
sudo systemctl restart opendmarc
wait # adiciona essa linha para esperar que o comando seja concluído

# Consolidar reinicializações ao final do script
echo "Recarregando e reiniciando os serviços..."
sudo systemctl restart postfix
echo "Reiniciando o serviço Dovecot..."
sudo systemctl restart dovecot

echo "==================================================== OpenDMARC ===================================================="

echo "==================================================== CLOUDFLARE ===================================================="

# Gerar código DKIM
DKIMCode=$(/root/dkimcode.sh)

# Obter o ID da zona do Cloudflare
echo "  -- Obtendo Zona"
CloudflareZoneID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$Domain&status=active" \
  -H "X-Auth-Email: $CloudflareEmail" \
  -H "X-Auth-Key: $CloudflareAPI" \
  -H "Content-Type: application/json" | jq -r '.result[0].id')

if [ -z "$CloudflareZoneID" ]; then
  echo "Erro: Não foi possível obter o ID da zona do Cloudflare." >&2
  exit 1
fi

# Função para obter detalhes de um registro existente
get_record_details() {
  local record_name=$1
  local record_type=$2
  curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records?name=$record_name&type=$record_type" \
    -H "X-Auth-Email: $CloudflareEmail" \
    -H "X-Auth-Key: $CloudflareAPI" \
    -H "Content-Type: application/json"
}

# Função para criar ou atualizar registros DNS
create_or_update_record() {
  local record_name=$1
  local record_type=$2
  local record_content=$3
  local record_ttl=120
  local record_priority=$4
  local record_proxied=false

  # Obter os detalhes do registro existente
  response=$(get_record_details "$record_name" "$record_type")
  existing_content=$(echo "$response" | jq -r '.result[0].content')
  existing_ttl=$(echo "$response" | jq -r '.result[0].ttl')
  existing_priority=$(echo "$response" | jq -r '.result[0].priority')

  # Verificar se o registro está atualizado
  if [ "$record_type" == "MX" ] && [ "$existing_content" == "$record_content" ] && [ "$existing_ttl" -eq "$record_ttl" ] && [ "$existing_priority" -eq "$record_priority" ]; then
    echo "Registro $record_type para $record_name já está atualizado. Pulando."
  elif [ "$record_type" != "MX" ] && [ "$existing_content" == "$record_content" ] && [ "$existing_ttl" -eq "$record_ttl" ]; then
    echo "Registro $record_type para $record_name já está atualizado. Pulando."
  else
    echo "  -- Criando ou atualizando registro $record_type para $record_name"
    if [ "$record_type" == "MX" ]; then
      data=$(jq -n --arg type "$record_type" --arg name "$record_name" --arg content "$record_content" --arg ttl "$record_ttl" --argjson proxied "$record_proxied" --arg priority "$record_priority" \
            '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber), proxied: $proxied, priority: ($priority | tonumber)}')
    else
      data=$(jq -n --arg type "$record_type" --arg name "$record_name" --arg content "$record_content" --arg ttl "$record_ttl" --argjson proxied "$record_proxied" \
            '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber), proxied: $proxied}')
    fi

    # Verificar se o JSON foi gerado corretamente
    if [ -z "$data" ]; then
      echo "Erro ao gerar o corpo do JSON. Verifique as variáveis." >&2
      return 1
    fi

    # Enviar a solicitação para criar ou atualizar o registro
    response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
         -H "X-Auth-Email: $CloudflareEmail" \
         -H "X-Auth-Key: $CloudflareAPI" \
         -H "Content-Type: application/json" \
         --data "$data")

    echo "$response"
  fi
}

# Criar ou atualizar registros DNS
echo "  -- Configurando registros DNS"
create_or_update_record "$DKIMSelector" "A" "$ServerIP" ""
create_or_update_record "$ServerName" "TXT" "\"v=spf1 a:$ServerName ~all\"" ""
#create_or_update_record "_dmarc.$ServerName" "TXT" "\"v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc@$ServerName; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r\"" ""
create_or_update_record "_dmarc.$ServerName" "TXT" "\"v=DMARC1; p=reject; rua=mailto:dmarc-reports@$ServerName; ruf=mailto:dmarc-reports@$ServerName; sp=reject; adkim=s; aspf=s\"" ""
EscapedDKIMCode=$(printf '%s' "$DKIMCode" | sed 's/\"/\\\"/g')
create_or_update_record "mail._domainkey.$ServerName" "TXT" "\"v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode\"" ""
create_or_update_record "$ServerName" "MX" "$ServerName" "10"
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

echo "================================================= Reiniciar servidor ================================================="
# Verificar se o reboot é necessário
if [ -f /var/run/reboot-required ]; then
  echo "Reiniciando o servidor em 5 segundos devido a atualizações críticas..."
  sleep 5
  sudo reboot
else
  echo "Reboot não necessário. Finalizando o script."
fi
