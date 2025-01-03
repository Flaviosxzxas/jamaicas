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

echo "==================================================== DKIM ======================================================="


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

# Função para configurar aliases
echo "Removendo comentário e atualizando o arquivo de aliases"

# Remover o comentário caso exista
sudo sed -i '/^# See man 5 aliases for format/d' /etc/aliases

# Adicionar o alias para contacto, caso ainda não exista
if ! grep -q "contacto:" /etc/aliases; then
    echo "contacto: contacto@$ServerName" | sudo tee -a /etc/aliases
else
    echo "Alias 'contacto' já existe em /etc/aliases"
fi

# Adicionar alias para o root, caso não exista
if ! grep -q "root:" /etc/aliases; then
    echo "root: contacto@$ServerName" | sudo tee -a /etc/aliases
else
    echo "Alias 'root' já existe em /etc/aliases"
fi

# Remover o banco de dados de aliases para garantir que seja regenerado
echo "Removendo banco de dados antigo de aliases..."
sudo rm -f /etc/aliases.db

# Atualizar aliases
echo "Atualizando aliases..."
sudo newaliases

# Instalar Postfix e outros pacotes necessários
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y postfix opendmarc pflogsumm
wait # adiciona essa linha para esperar que o comando seja concluído

# Configurações básicas do Postfix
debconf-set-selections <<< "postfix postfix/mailname string '"$ServerName"'"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
debconf-set-selections <<< "postfix postfix/destinations string '"$ServerName", localhost'"


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
# local_recipient_maps = proxy:unix:passwd.byname $alias_maps
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases

# DKIM Settings
milter_protocol = 6
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
    reject_unknown_recipient_domain,
    check_policy_service inet:127.0.0.1:10044

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

# Função para garantir que as dependências necessárias estejam instaladas
install_dependencies() {
    echo "Instalando dependências necessárias..."
    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get update -y || { echo "Erro ao atualizar o repositório"; exit 1; }

    # Verificar se o repositório universe está habilitado e habilitá-lo se necessário
    if ! grep -q "^deb .*universe" /etc/apt/sources.list; then
        echo "Habilitando repositório 'universe'..."
        sudo apt-add-repository "deb http://archive.ubuntu.com/ubuntu/ $(lsb_release -sc) universe" -y || { echo "Erro ao habilitar repositório 'universe'"; exit 1; }
        sudo apt-get update -y || { echo "Erro ao atualizar repositórios"; exit 1; }
    fi

    # Instalar pacotes via apt-get
    echo "Instalando pacotes necessários via apt-get..."
    if ! sudo apt-get install -y postfwd libsys-syslog-perl libnet-cidr-perl libmail-sender-perl libdata-dumper-perl libnet-dns-perl libmime-tools-perl liblog-any-perl perl postfix; then
        echo "Erro ao instalar dependências com apt-get. Tentando instalar pacotes Perl via CPAN." >&2

        # Verificar se o CPAN está instalado
        if ! command -v cpan &> /dev/null; then
            echo "CPAN não encontrado, instalando..."
            sudo apt-get install -y perl || { echo "Erro ao instalar Perl."; exit 1; }
            sudo cpan install Data::Dumper || { echo "Erro ao instalar Data::Dumper via CPAN."; exit 1; }
        else
            echo "Instalando pacotes Perl necessários via CPAN..."
            sudo cpan install Data::Dumper || { echo "Erro ao instalar Data::Dumper via CPAN."; exit 1; }
            sudo cpan install Sys::Syslog || { echo "Erro ao instalar Sys::Syslog via CPAN."; exit 1; }
            sudo cpan install Net::CIDR || { echo "Erro ao instalar Net::CIDR via CPAN."; exit 1; }
            sudo cpan install Mail::Sender || { echo "Erro ao instalar Mail::Sender via CPAN."; exit 1; }
            sudo cpan install Net::DNS || { echo "Erro ao instalar Net::DNS via CPAN."; exit 1; }
            sudo cpan install MIME::Tools || { echo "Erro ao instalar MIME::Tools via CPAN."; exit 1; }
            sudo cpan install Log::Any || { echo "Erro ao instalar Log::Any via CPAN."; exit 1; }
        fi
    fi
}

# Verificar se as dependências estão instaladas
echo "Verificando dependências..."
if ! dpkg -l | grep -q postfwd; then
    install_dependencies
else
    echo "Postfwd e dependências já instalados."
fi

# Continuar execução após instalação de dependências ou após erro
echo "Continuando a execução do script..."

# Criar usuário e grupo 'postfwd', se necessário
if ! id "postfwd" &>/dev/null; then
    echo "Usuário 'postfwd' não encontrado. Tentando criar..."

    # Tentar criar o grupo 'postfwd'
    if ! getent group postfwd &>/dev/null; then
        sudo groupadd postfwd || { echo "Erro ao criar grupo 'postfwd'. Abortando..."; exit 1; }
    fi

    # Tentar criar o usuário 'postfwd'
    sudo useradd -r -g postfwd -s /usr/sbin/nologin postfwd || { echo "Erro ao criar usuário 'postfwd'. Abortando..."; exit 1; }
else
    echo "Usuário 'postfwd' já existe."
fi

# Verificar novamente se o usuário foi criado corretamente
if ! id "postfwd" &>/dev/null; then
    echo "Erro: O usuário 'postfwd' não foi criado corretamente. Tentando recriar..."

    # Remover grupo e usuário corrompidos
    sudo groupdel postfwd &>/dev/null || true
    sudo userdel postfwd &>/dev/null || true

    # Criar novamente o grupo e o usuário
    sudo groupadd postfwd || { echo "Erro crítico ao criar grupo 'postfwd'. Abortando..."; exit 1; }
    sudo useradd -r -g postfwd -s /usr/sbin/nologin postfwd || { echo "Erro crítico ao criar usuário 'postfwd'. Abortando..."; exit 1; }
fi

echo "Usuário e grupo 'postfwd' configurados com sucesso."


# Garantir que o grupo 'nobody' exista
if ! getent group nobody &>/dev/null; then
    echo "Criando grupo 'nobody'..."
    sudo groupadd nobody || { echo "Erro ao criar grupo 'nobody'. Abortando..."; exit 1; }
else
    echo "Grupo 'nobody' já existe."
fi

# Instalar Postfwd, se não estiver instalado
if ! command -v postfwd &>/dev/null; then
    echo "Postfwd não encontrado. Instalando..."
    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get update -y && sudo apt-get install -y postfwd || { echo "Erro ao instalar o postfwd."; exit 1; }
else
    echo "Postfwd já está instalado."
fi

POSTFWD_CONF="/etc/postfix/postfwd.cf"

# Criar arquivo de configuração do Postfwd
if [ ! -f "$POSTFWD_CONF" ]; then
    echo "Arquivo de configuração $POSTFWD_CONF não encontrado. Criando..."
    sudo tee "$POSTFWD_CONF" > /dev/null <<EOF
pidfile=/run/postfwd/postfwd.pid
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

# Yahoo (Contas Pessoais)
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

# Google (Contas Pessoais e G Suite)
id=limit-google
pattern=recipient mx=.*google
action=rate(global/2000/3600) defer_if_permit "Limite de 2000 e-mails por hora atingido para Google."

# Hotmail (Contas Pessoais)
id=limit-hotmail
pattern=recipient mx=.*hotmail.com
action=rate(global/1000/86400) defer_if_permit "Limite de 1000 e-mails por dia atingido para Hotmail."

# Office 365 (Contas Empresariais)
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

# Provedores na Argentina
# Fibertel
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
action=rate(global /200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Telecom."

# Claro
id=limit-claro
pattern=recipient mx=.*claro.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Claro."

# Provedores no México
# Telmex
id=limit-telmex
pattern=recipient mx=.*prodigy.net.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Telmex."

# Axtel
id=limit-axtel
pattern=recipient mx=.*axtel.net
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Axtel."

# Izzi Telecom
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

# Outros (Sem Limite)
id=no-limit
pattern=recipient mx=.*
action=permit
EOF

    # Ajustar a propriedade e permissões do arquivo de configuração
    sudo chown postfwd:postfwd "$POSTFWD_CONF"  # Ajustar a propriedade do arquivo
    sudo chmod 640 "$POSTFWD_CONF"  # Ajustar as permissões do arquivo

else
    echo "Arquivo de configuração $POSTFWD_CONF já existe."
fi

# Criar e ajustar permissões do diretório de PID
echo "Criando e ajustando permissões do diretório de PID..."
sudo mkdir -p "/var/run/postfwd" || { echo "Erro ao criar diretório /var/run/postfwd."; exit 1; }
sudo chown postfwd:postfwd "/var/run/postfwd" || { echo "Erro ao ajustar proprietário do diretório /var/run/postfwd."; exit 1; }
sudo chmod 750 "/var/run/postfwd" || { echo "Erro ao ajustar permissões do diretório /var/run/postfwd."; exit 1; }

# Criar e ajustar permissões do diretório temporário para cache
echo "Criando e ajustando permissões do diretório temporário para cache..."
sudo mkdir -p "/var/tmp/postfwd" || { echo "Erro ao criar diretório /var/tmp/postfwd."; exit 1; }
sudo chown postfwd:postfwd "/var/tmp/postfwd" || { echo "Erro ao ajustar proprietário do diretório /var/tmp/postfwd."; exit 1; }
sudo chmod 750 "/var/tmp/postfwd" || { echo "Erro ao ajustar permissões do diretório /var/tmp/postfwd."; exit 1; }

echo "Permissões ajustadas com sucesso!"

# Criar arquivo de serviço systemd, se não existir
if [ ! -f /etc/systemd/system/postfwd.service ]; then
    echo "Criando arquivo de serviço systemd para postfwd..."
    sudo tee /etc/systemd/system/postfwd.service > /dev/null <<EOF
[Unit]
Description=Postfwd - Postfix Policy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/postfwd -f /etc/postfix/postfwd.cf -vv --pidfile /run/postfwd/postfwd.pid
PIDFile=/run/postfwd/postfwd.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable postfwd
else
    echo "Arquivo de serviço systemd já existe."
fi

# Adicionar Postfwd ao master.cf, se ainda não estiver presente
echo "Verificando se a entrada do Postfwd já está presente no /etc/postfix/master.cf..."
if ! grep -q "127.0.0.1:10040 inet" /etc/postfix/master.cf; then
    echo "Adicionando entrada do Postfwd ao /etc/postfix/master.cf..."
    sudo tee -a /etc/postfix/master.cf > /dev/null <<EOF

# Postfwd Policy Server
127.0.0.1:10040 inet  n  -  n  -  1  spawn
  user=postfwd argv=/usr/sbin/postfwd2 -f /etc/postfix/postfwd.cf
EOF
    echo "Entrada adicionada com sucesso!"
else
    echo "A entrada do Postfwd já existe no /etc/postfix/master.cf."
fi

# Iniciar e verificar o serviço postfwd
sudo systemctl start postfwd || { echo "Erro ao iniciar o serviço postfwd."; exit 1; }
sudo systemctl restart postfix || { echo "Erro ao reiniciar o Postfix."; exit 1; }
sudo systemctl restart postfwd || { echo "Erro ao reiniciar o serviço postfwd."; exit 1; }

# Verificar o status do serviço
sudo systemctl status postfwd --no-pager || { echo "Verifique manualmente o status do serviço postfwd."; exit 1; }

echo "Configuração do Postfwd concluída com sucesso!"



echo "==================================================== POSTFIX ===================================================="

echo "==================================================== OpenDMARC ===================================================="

# Configurar o debconf para modo não interativo globalmente
export DEBIAN_FRONTEND=noninteractive

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

echo "==================================================== OpenDMARC ===================================================="

echo "==================================================== CLOUDFLARE ===================================================="

# Verificar se o jq já está instalado
if ! command -v jq &> /dev/null; then
  echo "jq não encontrado. Instalando..."
  sudo apt-get update
  sudo apt-get install -y jq
else
  echo "jq já está instalado. Pulando instalação."
fi

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

# Atualização para garantir que o DKIM seja uma única string
DKIMCode=$(echo "$DKIMCode" | tr -d '\n' | tr -s ' ')  # Limpar quebras de linha e espaços extras
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
sudo systemctl restart apache2

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
  echo "Reboot não necessário. Aguardando 5 segundos para leitura antes de finalizar o script..."
  sleep 5
fi

# Finaliza o script explicitamente
echo "Finalizando o script."
exit 0
