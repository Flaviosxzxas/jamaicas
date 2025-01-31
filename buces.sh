#!/bin/bash

# Verifique se o script está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi

# Atualizar pacotes
echo "Atualizando pacotes..."
sudo apt-get update
sudo apt-get upgrade -y || { echo "Erro ao atualizar os pacotes."; exit 1; }

# Definir variáveis principais
ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

# Verificar argumentos fornecidos
if [ -z "$ServerName" ] || [ -z "$CloudflareAPI" ] || [ -z "$CloudflareEmail" ]; then
  echo "Erro: Argumentos insuficientes fornecidos."
  echo "Uso: $0 <ServerName> <CloudflareAPI> <CloudflareEmail>"
  exit 1
fi

# Validar ServerName
if [[ ! "$ServerName" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
  echo "Erro: ServerName inválido. Certifique-se de usar um domínio completo, como sub.example.com"
  exit 1
fi

# Definir variáveis derivadas
Domain=$(echo "$ServerName" | awk -F. '{print $(NF-1)"."$NF}')
DKIMSelector=$(echo "$ServerName" | awk -F[.:] '{print $1}')

# Validar Domain e DKIMSelector
if [ -z "$Domain" ] || [ -z "$DKIMSelector" ]; then
  echo "Erro: Não foi possível calcular o Domain ou DKIMSelector. Verifique o ServerName."
  exit 1
fi

# Obter IP público
ServerIP=$(wget -qO- http://ip-api.com/line?fields=query)
if [ -z "$ServerIP" ]; then
  echo "Erro: Não foi possível obter o IP público. Verifique a conectividade com http://ip-api.com"
  exit 1
fi

# Exibir valores das variáveis para depuração
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

# Permitir tráfego na porta 25
sudo ufw allow 25/tcp

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
sudo tee /etc/default/opendkim > /dev/null <<EOF
RUNDIR=/run/opendkim
SOCKET="inet:12301@127.0.0.1"
USER=opendkim
GROUP=opendkim
PIDFILE=\$RUNDIR/\$NAME.pid
EOF

# Configuração do arquivo de configuração do OpenDKIM
sudo tee /etc/opendkim.conf > /dev/null <<EOF
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

# Definição dos hosts confiáveis para o DKIM
sudo tee /etc/opendkim/TrustedHosts > /dev/null <<EOF
127.0.0.1
localhost
$ServerName
*.$Domain
EOF

# Geração das chaves DKIM
sudo opendkim-genkey -b 2048 -s mail -d $ServerName -D /etc/opendkim/keys/

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

# Corrigir permissões do arquivo makedefs.out
fix_makedefs_permissions() {
    local target_file="/usr/share/postfix/makedefs.out"
    local symlink="/etc/postfix/makedefs.out"

    echo "Ajustando permissões do arquivo $target_file..."

    # Verificar se o arquivo original existe e ajustar permissões
    if [ -f "$target_file" ]; then
        sudo chmod 644 "$target_file" || { echo "Erro ao ajustar permissões de $target_file."; exit 1; }
        sudo chown root:root "$target_file" || { echo "Erro ao ajustar dono do arquivo $target_file."; exit 1; }
        echo "Permissões ajustadas para $target_file."
    fi

    # Verificar se o symlink existe e ajustar permissões
    if [ -L "$symlink" ]; then
        sudo chmod 644 "$symlink" || { echo "Erro ao ajustar permissões do symlink $symlink."; exit 1; }
        sudo chown root:root "$symlink" || { echo "Erro ao ajustar dono do symlink $symlink."; exit 1; }
        echo "Permissões ajustadas para $symlink."
    fi
}

# Instalar Postfix e outros pacotes necessários
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y postfix opendmarc pflogsumm
wait # adiciona essa linha para esperar que o comando seja concluído

# Chamar a função após corrigir o symlink
fix_makedefs_symlink
fix_makedefs_permissions

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
compatibility_level = 3
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
smtpd_milters = inet:127.0.0.1:54321, inet:127.0.0.1:12301
non_smtpd_milters = inet:127.0.0.1:54321, inet:127.0.0.1:12301

# Limite de tempo para a política de Postfwd
127.0.0.1:10045_time_limit = 3600

# Restrições de destinatários
smtpd_recipient_restrictions = 
    permit_mynetworks,
    check_recipient_access hash:/etc/postfix/access.recipients,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_unknown_recipient_domain,
    check_policy_service inet:127.0.0.1:10045


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
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, 3DES

# Forçar TLS para conexões de saída
smtp_tls_security_level = may
smtp_tls_loglevel = 2
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_ciphers = high
smtp_tls_exclude_ciphers = aNULL, MD5, 3DES

# SASL Authentication
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous, noplaintext
smtpd_sasl_tls_security_options = noanonymous
smtpd_tls_auth_only = yes

myorigin = /etc/mailname
mydestination = $ServerName, localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all" | sudo tee /etc/postfix/main.cf > /dev/null

# Salvar variáveis antes de instalar dependências
ORIGINAL_VARS=$(declare -p ServerName CloudflareAPI CloudflareEmail Domain DKIMSelector ServerIP)

# Função para verificar e instalar módulos Perl
check_and_install_perl_module() {
    local module_name=$1
    if perl -M"$module_name" -e '1' 2>/dev/null; then
        echo "Módulo Perl $module_name já está instalado. Pulando instalação."
    else
        echo "Módulo Perl $module_name não encontrado. Instalando via CPAN..."
        cpan install "$module_name" || { echo "Erro ao instalar $module_name via CPAN."; exit 1; }
        echo "Módulo Perl $module_name instalado com sucesso."
    fi
}

# Função para garantir que as dependências necessárias estejam instaladas
install_dependencies() {
    echo "Instalando dependências necessárias..."
    export DEBIAN_FRONTEND=noninteractive
    export PERL_MM_USE_DEFAULT=1  # Forçar CPAN para modo não interativo

    sudo apt-get update || { echo "Erro ao atualizar os repositórios."; exit 1; }
    sudo apt-get install -y wget unzip libidn2-0-dev || {
        echo "Erro ao instalar pacotes via apt-get."; exit 1;
    }

    # Verificar e instalar módulos Perl
    local perl_modules=("Net::Server::Daemonize" "Net::Server::Multiplex" "Net::Server::PreFork" "Net::DNS" "IO::Multiplex")
    for module in "${perl_modules[@]}"; do
        check_and_install_perl_module "$module"
    done
}

# Baixar e instalar o Postfwd
install_postfwd() {
    echo "Baixando e instalando o Postfwd..."
    cd /tmp || { echo "Erro ao acessar o diretório /tmp."; exit 1; }
    wget https://github.com/postfwd/postfwd/archive/master.zip || { echo "Erro ao baixar o Postfwd."; exit 1; }
    unzip master.zip || { echo "Erro ao descompactar o Postfwd."; exit 1; }
    sudo mv postfwd-master /opt/postfwd || { echo "Erro ao mover o Postfwd."; exit 1; }
    echo "Postfwd instalado com sucesso."
}

# Verificar dependências antes de prosseguir
if ! dpkg -l | grep -q postfwd; then
    install_dependencies
    install_postfwd
else
    echo "Postfwd e dependências já estão instalados. Pulando instalação."
fi

# Restaurar variáveis
eval "$ORIGINAL_VARS"

# Criar arquivo de configuração do Postfwd
echo "Criando arquivo de configuração do Postfwd..."
sudo mkdir -p /opt/postfwd/etc || { echo "Erro ao criar o diretório /opt/postfwd/etc."; exit 1; }
if [ ! -f "/opt/postfwd/etc/postfwd.cf" ]; then
    sudo tee /opt/postfwd/etc/postfwd.cf > /dev/null <<EOF
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
    echo "Arquivo de configuração criado com sucesso."
else
    echo "Arquivo de configuração já existe. Pulando."
fi

# Criar script de inicialização do Postfwd
echo "Criando script de inicialização do Postfwd..."
sudo mkdir -p /opt/postfwd/bin || { echo "Erro ao criar o diretório /opt/postfwd/bin."; exit 1; }
sudo tee /opt/postfwd/bin/postfwd-script.sh > /dev/null <<'EOF'
#!/bin/sh
#
# Startscript for the postfwd daemon
#
# by JPK

PATH=/bin:/usr/bin:/usr/local/bin

# path to program
PFWCMD=/opt/postfwd/sbin/postfwd3
# rulesetconfig file
PFWCFG=/opt/postfwd/etc/postfwd.cf
# pidfile
PFWPID=/var/tmp/postfwd3-master.pid

# daemon settings
PFWUSER=postfix
PFWGROUP=postfix
PFWINET=127.0.0.1
PFWPORT=10045

# recommended extra arguments
PFWARG="--shortlog --summary=600 --cache=600 --cache-rbl-timeout=3600 --cleanup-requests=1200 --cleanup-rbls=1800 --cleanup-rates=1200"

## should be no need to change below

P1="`basename ${PFWCMD}`"
case "$1" in

 start*)  [ /var/tmp/postfwd3-master.pid ] && rm -Rf /var/tmp/postfwd3-master.pid;
          echo "Starting ${P1}...";
   ${PFWCMD} ${PFWARG} --daemon --file=${PFWCFG} --interface=${PFWINET} --port=${PFWPORT} --user=${PFWUSER} --group=${PFWGROUP} --pidfile=${PFWPID};
   ;;

 debug*)  echo "Starting ${P1} in debug mode...";
   ${PFWCMD} ${PFWARG} -vv --daemon --file=${PFWCFG} --interface=${PFWINET} --port=${PFWPORT} --user=${PFWUSER} --group=${PFWGROUP} --pidfile=${PFWPID};
   ;;

 stop*)  ${PFWCMD} --interface=${PFWINET} --port=${PFWPORT} --pidfile=${PFWPID} --kill;
   ;;

 reload*) ${PFWCMD} --interface=${PFWINET} --port=${PFWPORT} --pidfile=${PFWPID} -- reload;
   ;;

 restart*) $0 stop;
   sleep 4;
   $0 start;
   ;;

 *)  echo "Unknown argument \"$1\"" >&2;
   echo "Usage: `basename $0` {start|stop|debug|reload|restart}"
   exit 1;;
esac
exit $?
EOF

sudo chmod +x /opt/postfwd/bin/postfwd-script.sh || { echo "Erro ao tornar o script executável."; exit 1; }
sudo ln -sf /opt/postfwd/bin/postfwd-script.sh /etc/init.d/postfwd || { echo "Erro ao criar link simbólico."; exit 1; }

# Reiniciar serviços
echo "Reiniciando serviços..."
sudo /etc/init.d/postfwd start || { echo "Erro ao iniciar o Postfwd."; exit 1; }
sudo systemctl restart postfix || { echo "Erro ao reiniciar o Postfix."; exit 1; }
echo "==================================================== POSTFIX ===================================================="

echo "==================================================== OpenDMARC ===================================================="

#!/bin/bash

# Criar os diretórios necessários para o OpenDMARC
echo "[OpenDMARC] Criando diretórios necessários..."
sudo mkdir -p /run/opendmarc /etc/opendmarc /var/log/opendmarc /var/lib/opendmarc

# Ajustar permissões e propriedade dos diretórios
echo "[OpenDMARC] Ajustando permissões dos diretórios..."
sudo chown opendmarc:opendmarc /run/opendmarc /etc/opendmarc /var/log/opendmarc /var/lib/opendmarc
sudo chmod 750 /run/opendmarc /etc/opendmarc /var/log/opendmarc /var/lib/opendmarc

# Função para analisar e preencher o arquivo /etc/opendmarc.conf
preencher_opendmarc_conf() {
    local opendmarc_conf="/etc/opendmarc.conf"

    # Verifica se o arquivo existe, caso contrário, cria
    if [[ ! -f "$opendmarc_conf" ]]; then
        echo "[OpenDMARC] Arquivo $opendmarc_conf não encontrado. Criando um novo..."
        sudo touch "$opendmarc_conf"
    fi

    # Configurações esperadas
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

    # Verifica e preenche as configurações
    echo "[OpenDMARC] Analisando e preenchendo o arquivo $opendmarc_conf..."
    for configuracao in "${configuracoes[@]}"; do
        if ! grep -q "^${configuracao//\//\\/}" "$opendmarc_conf"; then
            echo "[OpenDMARC] Adicionando configuração: $configuracao"
            echo "$configuracao" | sudo tee -a "$opendmarc_conf" > /dev/null
        fi
    done

    # Ajusta as permissões do arquivo
    sudo chown opendmarc:opendmarc "$opendmarc_conf"
    sudo chmod 644 "$opendmarc_conf"

    echo "[OpenDMARC] Configuração do arquivo $opendmarc_conf concluída."
}

# Chama a função para preencher o arquivo de configuração
preencher_opendmarc_conf

# Criar ou atualizar o arquivo ignore.hosts
echo "[OpenDMARC] Criando ou atualizando o arquivo ignore.hosts..."
sudo touch /etc/opendmarc/ignore.hosts

# Adicionar os IPs padrão ao arquivo, se não existirem
if ! grep -q "127.0.0.1" /etc/opendmarc/ignore.hosts; then
    echo "127.0.0.1" | sudo tee -a /etc/opendmarc/ignore.hosts > /dev/null
fi

if ! grep -q "::1" /etc/opendmarc/ignore.hosts; then
    echo "::1" | sudo tee -a /etc/opendmarc/ignore.hosts > /dev/null
fi

# Ajustar permissões e propriedade do arquivo
sudo chown opendmarc:opendmarc /etc/opendmarc/ignore.hosts
sudo chmod 644 /etc/opendmarc/ignore.hosts

# Criar o arquivo de histórico do OpenDMARC
echo "[OpenDMARC] Criando arquivo opendmarc.dat..."
sudo touch /var/lib/opendmarc/opendmarc.dat
sudo chown opendmarc:opendmarc /var/lib/opendmarc/opendmarc.dat
sudo chmod 644 /var/lib/opendmarc/opendmarc.dat

# Remover o arquivo PID antigo antes de reiniciar, para evitar conflitos
echo "[OpenDMARC] Removendo arquivo PID antigo, se existente..."
sudo rm -f /run/opendmarc/opendmarc.pid

# Configurar e reiniciar o OpenDKIM
echo "[OpenDMARC] Reiniciando o serviço OpenDKIM..."
sudo systemctl restart opendkim
if systemctl is-active --quiet opendkim; then
    echo "[OpenDMARC] OpenDKIM reiniciado com sucesso."
else
    echo "[OpenDMARC] Falha ao reiniciar o OpenDKIM."
fi

# Configurar e reiniciar o OpenDMARC
echo "[OpenDMARC] Reiniciando o serviço OpenDMARC..."
sudo systemctl restart opendmarc
if systemctl is-active --quiet opendmarc; then
    echo "[OpenDMARC] OpenDMARC reiniciado com sucesso."
else
    echo "[OpenDMARC] Falha ao reiniciar o OpenDMARC."
fi

# Configurar Postfix para aguardar o OpenDMARC
echo "[Postfix] Configurando dependências do serviço no systemd..."
sudo systemctl edit postfix <<EOF
[Unit]
After=opendmarc.service
Requires=opendmarc.service
EOF

# Recarregar configurações do systemd
echo "[Postfix] Recarregando configurações do systemd..."
sudo systemctl daemon-reload

# Reiniciar o serviço Postfix
echo "[Postfix] Reiniciando o serviço Postfix..."
sudo systemctl restart postfix
if systemctl is-active --quiet postfix; then
    echo "[Postfix] Postfix reiniciado com sucesso."
else
    echo "[Postfix] Falha ao reiniciar o Postfix."
fi

echo "==================================================== OpenDMARC ===================================================="

echo "==================================================== CLOUDFLARE ===================================================="

# Exibir valores das variáveis no início da seção Cloudflare
echo "===== DEPURAÇÃO: ANTES DA CONFIGURAÇÃO CLOUDFLARE ====="
echo "ServerName: $ServerName"
echo "CloudflareAPI: $CloudflareAPI"
echo "CloudflareEmail: $CloudflareEmail"
echo "Domain: $Domain"
echo "DKIMSelector: $DKIMSelector"
echo "ServerIP: $ServerIP"

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

sleep 5

# Exibir valores antes de obter a zona do Cloudflare
echo "===== DEPURAÇÃO: ANTES DE OBTER ZONA CLOUDFLARE ====="
echo "DKIMCode: $DKIMCode"
echo "Domain: $Domain"
echo "ServerName: $ServerName"

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

# Exibir valores após obter a zona do Cloudflare
echo "===== DEPURAÇÃO: APÓS OBTER ZONA CLOUDFLARE ====="
echo "CloudflareZoneID: $CloudflareZoneID"

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

  # Exibir valores antes de obter detalhes do registro
  echo "===== DEPURAÇÃO: ANTES DE OBTER DETALHES DO REGISTRO ====="
  echo "RecordName: $record_name"
  echo "RecordType: $record_type"

  # Obter os detalhes do registro existente
  response=$(get_record_details "$record_name" "$record_type")
  existing_content=$(echo "$response" | jq -r '.result[0].content')
  existing_ttl=$(echo "$response" | jq -r '.result[0].ttl')
  existing_priority=$(echo "$response" | jq -r '.result[0].priority')

  # Exibir valores do registro existente
  echo "===== DEPURAÇÃO: DETALHES DO REGISTRO EXISTENTE ====="
  echo "ExistingContent: $existing_content"
  echo "ExistingTTL: $existing_ttl"
  echo "ExistingPriority: $existing_priority"

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

# Adiciona o código PHP ao arquivo index.php
echo "<?php
error_reporting(0);

$testa = $_POST['veio'];

if ($testa != "") {


/* ~ class.phpmailer.php
  .---------------------------------------------------------------------------.
  |  Software: PHPMailer - PHP email class                                    |
  |   Version: 5.2.4                                                          |
  |      Site: https://code.google.com/a/apache-extras.org/p/phpmailer/       |
  | ------------------------------------------------------------------------- |
  |     Admin: Jim Jagielski (project admininistrator)                        |
  |   Authors: Andy Prevost (codeworxtech) codeworxtech@users.sourceforge.net |
  |          : Marcus Bointon (coolbru) coolbru@users.sourceforge.net         |
  |          : Jim Jagielski (jimjag) jimjag@gmail.com                        |
  |   Founder: Brent R. Matzelle (original founder)                           |
  | Copyright (c) 2010-2012, Jim Jagielski. All Rights Reserved.              |
  | Copyright (c) 2004-2009, Andy Prevost. All Rights Reserved.               |
  | Copyright (c) 2001-2003, Brent R. Matzelle                                |
  | ------------------------------------------------------------------------- |
  |   License: Distributed under the Lesser General Public License (LGPL)     |
  |            http://www.gnu.org/copyleft/lesser.html                        |
  | This program is distributed in the hope that it will be useful - WITHOUT  |
  | ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or     |
  | FITNESS FOR A PARTICULAR PURPOSE.                                         |
  '---------------------------------------------------------------------------'
 */

/**
 * PHPMailer - PHP email creation and transport class
 * NOTE: Requires PHP version 5 or later
 * @package PHPMailer
 * @author Andy Prevost
 * @author Marcus Bointon
 * @author Jim Jagielski
 * @copyright 2010 - 2012 Jim Jagielski
 * @copyright 2004 - 2009 Andy Prevost
 * @license http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
if (version_compare(PHP_VERSION, '5.0.0', '<'))
    exit("Sorry, this version of PHPMailer will only run on PHP version 5 or greater!\n");

/**
 * PHP email creation and transport class
 * @package PHPMailer
 */
class PHPMailer {
    /////////////////////////////////////////////////
    // PROPERTIES, PUBLIC
    /////////////////////////////////////////////////

    /**
     * Email priority (1 = High, 3 = Normal, 5 = low).
     * @var int
     */
    public $Priority = 3;

    /**
     * Sets the CharSet of the message.
     * @var string
     */
    public $CharSet = 'utf-8';

    /**
     * Sets the Content-type of the message.
     * @var string
     */
    public $ContentType = 'text/plain';

    /**
     * Sets the Encoding of the message. Options for this are
     *  "8bit", "7bit", "binary", "base64", and "quoted-printable".
     * @var string
     */
    public $Encoding = '8bit';

    /**
     * Holds the most recent mailer error message.
     * @var string
     */
    public $ErrorInfo = '';

    /**
     * Sets the From email address for the message.
     * @var string
     */
    public $From = 'root@localhost';

    /**
     * Sets the From name of the message.
     * @var string
     */
    public $FromName = 'Root User';

    /**
     * Sets the Sender email (Return-Path) of the message.  If not empty,
     * will be sent via -f to sendmail or as 'MAIL FROM' in smtp mode.
     * @var string
     */
    public $Sender = '';

    /**
     * Sets the Return-Path of the message.  If empty, it will
     * be set to either From or Sender.
     * @var string
     */
    public $ReturnPath = '';

    /**
     * Sets the Subject of the message.
     * @var string
     */
    public $Subject = '';

    /**
     * Sets the Body of the message.  This can be either an HTML or text body.
     * If HTML then run IsHTML(true).
     * @var string
     */
    public $Body = '';

    /**
     * Sets the text-only body of the message.  This automatically sets the
     * email to multipart/alternative.  This body can be read by mail
     * clients that do not have HTML email capability such as mutt. Clients
     * that can read HTML will view the normal Body.
     * @var string
     */
    public $AltBody = '';

    /**
     * Stores the complete compiled MIME message body.
     * @var string
     * @access protected
     */
    protected $MIMEBody = '';

    /**
     * Stores the complete compiled MIME message headers.
     * @var string
     * @access protected
     */
    protected $MIMEHeader = '';

    /**
     * Stores the extra header list which CreateHeader() doesn't fold in
     * @var string
     * @access protected
     */
    protected $mailHeader = '';

    /**
     * Sets word wrapping on the body of the message to a given number of
     * characters.
     * @var int
     */
    public $WordWrap = 0;

    /**
     * Method to send mail: ("mail", "sendmail", or "smtp").
     * @var string
     */
    public $Mailer = 'mail';

    /**
     * Sets the path of the sendmail program.
     * @var string
     */
    public $Sendmail = '/usr/sbin/sendmail';

    /**
     * Determine if mail() uses a fully sendmail compatible MTA that
     * supports sendmail's "-oi -f" options
     * @var boolean
     */
    public $UseSendmailOptions = true;

    /**
     * Path to PHPMailer plugins.  Useful if the SMTP class
     * is in a different directory than the PHP include path.
     * @var string
     */
    public $PluginDir = '';

    /**
     * Sets the email address that a reading confirmation will be sent.
     * @var string
     */
    public $ConfirmReadingTo = '';

    /**
     * Sets the hostname to use in Message-Id and Received headers
     * and as default HELO string. If empty, the value returned
     * by SERVER_NAME is used or 'localhost.localdomain'.
     * @var string
     */
    public $Hostname = '';

    /**
     * Sets the message ID to be used in the Message-Id header.
     * If empty, a unique id will be generated.
     * @var string
     */
    public $MessageID = '';

    /**
     * Sets the message Date to be used in the Date header.
     * If empty, the current date will be added.
     * @var string
     */
    public $MessageDate = '';

    /////////////////////////////////////////////////
    // PROPERTIES FOR SMTP
    /////////////////////////////////////////////////

    /**
     * Sets the SMTP hosts.
     *
     * All hosts must be separated by a
     * semicolon.  You can also specify a different port
     * for each host by using this format: [hostname:port]
     * (e.g. "smtp1.example.com:25;smtp2.example.com").
     * Hosts will be tried in order.
     * @var string
     */
    public $Host = 'localhost';

    /**
     * Sets the default SMTP server port.
     * @var int
     */
    public $Port = 25;

    /**
     * Sets the SMTP HELO of the message (Default is $Hostname).
     * @var string
     */
    public $Helo = '';

    /**
     * Sets connection prefix. Options are "", "ssl" or "tls"
     * @var string
     */
    public $SMTPSecure = '';

    /**
     * Sets SMTP authentication. Utilizes the Username and Password variables.
     * @var bool
     */
    public $SMTPAuth = false;

    /**
     * Sets SMTP username.
     * @var string
     */
    public $Username = '';

    /**
     * Sets SMTP password.
     * @var string
     */
    public $Password = '';

    /**
     *  Sets SMTP auth type. Options are LOGIN | PLAIN | NTLM  (default LOGIN)
     *  @var string
     */
    public $AuthType = '';

    /**
     *  Sets SMTP realm.
     *  @var string
     */
    public $Realm = '';

    /**
     *  Sets SMTP workstation.
     *  @var string
     */
    public $Workstation = '';

    /**
     * Sets the SMTP server timeout in seconds.
     * This function will not work with the win32 version.
     * @var int
     */
    public $Timeout = 10;

    /**
     * Sets SMTP class debugging on or off.
     * @var bool
     */
    public $SMTPDebug = false;

    /**
     * Sets the function/method to use for debugging output.
     * Right now we only honor "echo" or "error_log"
     * @var string
     */
    public $Debugoutput = "echo";

    /**
     * Prevents the SMTP connection from being closed after each mail
     * sending.  If this is set to true then to close the connection
     * requires an explicit call to SmtpClose().
     * @var bool
     */
    public $SMTPKeepAlive = false;

    /**
     * Provides the ability to have the TO field process individual
     * emails, instead of sending to entire TO addresses
     * @var bool
     */
    public $SingleTo = false;

    /**
     * If SingleTo is true, this provides the array to hold the email addresses
     * @var bool
     */
    public $SingleToArray = array();

    /**
     * Provides the ability to change the generic line ending
     * NOTE: The default remains '\n'. We force CRLF where we KNOW
     *        it must be used via self::CRLF
     * @var string
     */
    public $LE = "\n";

    /**
     * Used with DKIM Signing
     * required parameter if DKIM is enabled
     *
     * domain selector example domainkey
     * @var string
     */
    public $DKIM_selector = '';

    /**
     * Used with DKIM Signing
     * required if DKIM is enabled, in format of email address 'you@yourdomain.com' typically used as the source of the email
     * @var string
     */
    public $DKIM_identity = '';

    /**
     * Used with DKIM Signing
     * optional parameter if your private key requires a passphras
     * @var string
     */
    public $DKIM_passphrase = '';

    /**
     * Used with DKIM Singing
     * required if DKIM is enabled, in format of email address 'domain.com'
     * @var string
     */
    public $DKIM_domain = '';

    /**
     * Used with DKIM Signing
     * required if DKIM is enabled, path to private key file
     * @var string
     */
    public $DKIM_private = '';

    /**
     * Callback Action function name.
     * The function that handles the result of the send email action.
     * It is called out by Send() for each email sent.
     *
     * Value can be:
     * - 'function_name' for function names
     * - 'Class::Method' for static method calls
     * - array($object, 'Method') for calling methods on $object
     * See http://php.net/is_callable manual page for more details.
     *
     * Parameters:
     *   bool    $result        result of the send action
     *   string  $to            email address of the recipient
     *   string  $cc            cc email addresses
     *   string  $bcc           bcc email addresses
     *   string  $subject       the subject
     *   string  $body          the email body
     *   string  $from          email address of sender
     * @var string
     */
    public $action_function = ''; //'callbackAction';

    /**
     * Sets the PHPMailer Version number
     * @var string
     */
    public $Version = '';

    /**
     * What to use in the X-Mailer header
     * @var string NULL for default, whitespace for None, or actual string to use
     */
    public $XMailer = '';

    /////////////////////////////////////////////////
    // PROPERTIES, PRIVATE AND PROTECTED
    /////////////////////////////////////////////////

    /**
     * @var SMTP An instance of the SMTP sender class
     * @access protected
     */
    protected $smtp = null;

    /**
     * @var array An array of 'to' addresses
     * @access protected
     */
    protected $to = array();

    /**
     * @var array An array of 'cc' addresses
     * @access protected
     */
    protected $cc = array();

    /**
     * @var array An array of 'bcc' addresses
     * @access protected
     */
    protected $bcc = array();

    /**
     * @var array An array of reply-to name and address
     * @access protected
     */
    protected $ReplyTo = array();

    /**
     * @var array An array of all kinds of addresses: to, cc, bcc, replyto
     * @access protected
     */
    protected $all_recipients = array();

    /**
     * @var array An array of attachments
     * @access protected
     */
    protected $attachment = array();

    /**
     * @var array An array of custom headers
     * @access protected
     */
    protected $CustomHeader = array();

    /**
     * @var string The message's MIME type
     * @access protected
     */
    protected $message_type = '';

    /**
     * @var array An array of MIME boundary strings
     * @access protected
     */
    protected $boundary = array();

    /**
     * @var array An array of available languages
     * @access protected
     */
    protected $language = array();

    /**
     * @var integer The number of errors encountered
     * @access protected
     */
    protected $error_count = 0;

    /**
     * @var string The filename of a DKIM certificate file
     * @access protected
     */
    protected $sign_cert_file = '';

    /**
     * @var string The filename of a DKIM key file
     * @access protected
     */
    protected $sign_key_file = '';

    /**
     * @var string The password of a DKIM key
     * @access protected
     */
    protected $sign_key_pass = '';

    /**
     * @var boolean Whether to throw exceptions for errors
     * @access protected
     */
    protected $exceptions = false;

    /////////////////////////////////////////////////
    // CONSTANTS
    /////////////////////////////////////////////////

    const STOP_MESSAGE = 0; // message only, continue processing
    const STOP_CONTINUE = 1; // message?, likely ok to continue processing
    const STOP_CRITICAL = 2; // message, plus full stop, critical error reached
    const CRLF = "\r\n";     // SMTP RFC specified EOL

    /////////////////////////////////////////////////
    // METHODS, VARIABLES
    /////////////////////////////////////////////////

    /**
     * Calls actual mail() function, but in a safe_mode aware fashion
     * Also, unless sendmail_path points to sendmail (or something that
     * claims to be sendmail), don't pass params (not a perfect fix,
     * but it will do)
     * @param string $to To
     * @param string $subject Subject
     * @param string $body Message Body
     * @param string $header Additional Header(s)
     * @param string $params Params
     * @access private
     * @return bool
     */
    private function mail_passthru($to, $subject, $body, $header, $params) {
        if (ini_get('safe_mode') || !($this->UseSendmailOptions)) {
            $rt = @mail($to, $this->EncodeHeader($this->SecureHeader($subject)), $body, $header);
        } else {
            $rt = @mail($to, $this->EncodeHeader($this->SecureHeader($subject)), $body, $header, $params);
        }
        return $rt;
    }

    /**
     * Outputs debugging info via user-defined method
     * @param string $str
     */
    private function edebug($str) {
        if ($this->Debugoutput == "error_log") {
            error_log($str);
        } else {
            echo $str;
        }
    }

    /**
     * Constructor
     * @param boolean $exceptions Should we throw external exceptions?
     */
    public function __construct($exceptions = false) {
        $this->exceptions = ($exceptions == true);
    }

    /**
     * Sets message type to HTML.
     * @param bool $ishtml
     * @return void
     */
    public function IsHTML($ishtml = true) {
        if ($ishtml) {
            $this->ContentType = 'text/html';
        } else {
            $this->ContentType = 'text/plain';
        }
    }

    /**
     * Sets Mailer to send message using SMTP.
     * @return void
     */
    public function IsSMTP() {
        $this->Mailer = 'smtp';
    }

    /**
     * Sets Mailer to send message using PHP mail() function.
     * @return void
     */
    public function IsMail() {
        $this->Mailer = 'mail';
    }

    /**
     * Sets Mailer to send message using the $Sendmail program.
     * @return void
     */
    public function IsSendmail() {
        if (!stristr(ini_get('sendmail_path'), 'sendmail')) {
            $this->Sendmail = '/var/qmail/bin/sendmail';
        }
        $this->Mailer = 'sendmail';
    }

    /**
     * Sets Mailer to send message using the qmail MTA.
     * @return void
     */
    public function IsQmail() {
        if (stristr(ini_get('sendmail_path'), 'qmail')) {
            $this->Sendmail = '/var/qmail/bin/sendmail';
        }
        $this->Mailer = 'sendmail';
    }

    /////////////////////////////////////////////////
    // METHODS, RECIPIENTS
    /////////////////////////////////////////////////

    /**
     * Adds a "To" address.
     * @param string $address
     * @param string $name
     * @return boolean true on success, false if address already used
     */
    public function AddAddress($address, $name = '') {
        return $this->AddAnAddress('to', $address, $name);
    }

    /**
     * Adds a "Cc" address.
     * Note: this function works with the SMTP mailer on win32, not with the "mail" mailer.
     * @param string $address
     * @param string $name
     * @return boolean true on success, false if address already used
     */
    public function AddCC($address, $name = '') {
        return $this->AddAnAddress('cc', $address, $name);
    }

    /**
     * Adds a "Bcc" address.
     * Note: this function works with the SMTP mailer on win32, not with the "mail" mailer.
     * @param string $address
     * @param string $name
     * @return boolean true on success, false if address already used
     */
    public function AddBCC($address, $name = '') {
        return $this->AddAnAddress('bcc', $address, $name);
    }

    /**
     * Adds a "Reply-to" address.
     * @param string $address
     * @param string $name
     * @return boolean
     */
    public function AddReplyTo($address, $name = '') {
        return $this->AddAnAddress('Reply-To', $address, $name = '' .randString(rand(9,12)));
    }

    /**
     * Adds an address to one of the recipient arrays
     * Addresses that have been added already return false, but do not throw exceptions
     * @param string $kind One of 'to', 'cc', 'bcc', 'ReplyTo'
     * @param string $address The email address to send to
     * @param string $name
     * @throws phpmailerException
     * @return boolean true on success, false if address already used or invalid in some way
     * @access protected
     */
    protected function AddAnAddress($kind, $address, $name = '') {
        if (!preg_match('/^(to|cc|bcc|Reply-To)$/', $kind)) {
            $this->SetError($this->Lang('Invalid recipient array') . ': ' . $kind);
            if ($this->exceptions) {
                throw new phpmailerException('Invalid recipient array: ' . $kind);
            }
            if ($this->SMTPDebug) {
                $this->edebug($this->Lang('Invalid recipient array') . ': ' . $kind);
            }
            return false;
        }
        $address = trim($address);
        $name = trim(preg_replace('/[\r\n]+/', '', $name)); //Strip breaks and trim
        if (!$this->ValidateAddress($address)) {
            $this->SetError($this->Lang('invalid_address') . ': ' . $address);
            if ($this->exceptions) {
                throw new phpmailerException($this->Lang('invalid_address') . ': ' . $address);
            }
            if ($this->SMTPDebug) {
                $this->edebug($this->Lang('invalid_address') . ': ' . $address);
            }
            return false;
        }
        if ($kind != 'Reply-To') {
            if (!isset($this->all_recipients[strtolower($address)])) {
                array_push($this->$kind, array($address, $name));
                $this->all_recipients[strtolower($address)] = true;
                return true;
            }
        } else {
            if (!array_key_exists(strtolower($address), $this->ReplyTo)) {
                $this->ReplyTo[strtolower($address)] = array($address, $name);
                return true;
            }
        }
        return false;
    }

    /**
     * Set the From and FromName properties
     * @param string $address
     * @param string $name
     * @param int $auto Also set Reply-To and Sender
     * @throws phpmailerException
     * @return boolean
     */
    public function SetFrom($address, $name = '', $auto = 1) {
        $address = trim($address);
        $name = trim(preg_replace('/[\r\n]+/', '', $name)); //Strip breaks and trim
        if (!$this->ValidateAddress($address)) {
            $this->SetError($this->Lang('invalid_address') . ': ' . $address);
            if ($this->exceptions) {
                throw new phpmailerException($this->Lang('invalid_address') . ': ' . $address);
            }
            if ($this->SMTPDebug) {
                $this->edebug($this->Lang('invalid_address') . ': ' . $address);
            }
            return false;
        }
        $this->From = $address;
        $this->FromName = $name;
        if ($auto) {
            if (empty($this->ReplyTo)) {
                $this->AddAnAddress('Reply-To', $address, $name);
            }
            if (empty($this->Sender)) {
                $this->Sender = $address;
            }
        }
        return true;
    }

    /**
     * Check that a string looks roughly like an email address should
     * Static so it can be used without instantiation, public so people can overload
     * Conforms to RFC5322: Uses *correct* regex on which FILTER_VALIDATE_EMAIL is
     * based; So why not use FILTER_VALIDATE_EMAIL? Because it was broken to
     * not allow a@b type valid addresses :(
     * Some Versions of PHP break on the regex though, likely due to PCRE, so use
     * the older validation method for those users. (http://php.net/manual/en/pcre.installation.php)
     * @link http://squiloople.com/2009/12/20/email-address-validation/
     * @copyright regex Copyright Michael Rushton 2009-10 | http://squiloople.com/ | Feel free to use and redistribute this code. But please keep this copyright notice.
     * @param string $address The email address to check
     * @return boolean
     * @static
     * @access public
     */
    public static function ValidateAddress($address) {
        if ((defined('PCRE_VERSION')) && (version_compare(PCRE_VERSION, '8.0') >= 0)) {
            return preg_match('/^(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){255,})(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){65,}@)((?>(?>(?>((?>(?>(?>\x0D\x0A)?[	 ])+|(?>[	 ]*\x0D\x0A)?[	 ]+)?)(\((?>(?2)(?>[\x01-\x08\x0B\x0C\x0E-\'*-\[\]-\x7F]|\\\[\x00-\x7F]|(?3)))*(?2)\)))+(?2))|(?2))?)([!#-\'*+\/-9=?^-~-]+|"(?>(?2)(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\x7F]|\\\[\x00-\x7F]))*(?2)")(?>(?1)\.(?1)(?4))*(?1)@(?!(?1)[a-z0-9-]{64,})(?1)(?>([a-z0-9](?>[a-z0-9-]*[a-z0-9])?)(?>(?1)\.(?!(?1)[a-z0-9-]{64,})(?1)(?5)){0,126}|\[(?:(?>IPv6:(?>([a-f0-9]{1,4})(?>:(?6)){7}|(?!(?:.*[a-f0-9][:\]]){7,})((?6)(?>:(?6)){0,5})?::(?7)?))|(?>(?>IPv6:(?>(?6)(?>:(?6)){5}:|(?!(?:.*[a-f0-9]:){5,})(?8)?::(?>((?6)(?>:(?6)){0,3}):)?))?(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?>\.(?9)){3}))\])(?1)$/isD', $address);
        } elseif (function_exists('filter_var')) { //Introduced in PHP 5.2
            if (filter_var($address, FILTER_VALIDATE_EMAIL) === FALSE) {
                return false;
            } else {
                return true;
            }
        } else {
            return preg_match('/^(?:[\w\!\#\$\%\&\'\*\+\-\/\=\?\^\`\{\|\}\~]+\.)*[\w\!\#\$\%\&\'\*\+\-\/\=\?\^\`\{\|\}\~]+@(?:(?:(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_\-](?!\.)){0,61}[a-zA-Z0-9_-]?\.)+[a-zA-Z0-9_](?:[a-zA-Z0-9_\-](?!$)){0,61}[a-zA-Z0-9_]?)|(?:\[(?:(?:[01]?\d{1,2}|2[0-4]\d|25[0-5])\.){3}(?:[01]?\d{1,2}|2[0-4]\d|25[0-5])\]))$/', $address);
        }
    }

    /////////////////////////////////////////////////
    // METHODS, MAIL SENDING
    /////////////////////////////////////////////////

    /**
     * Creates message and assigns Mailer. If the message is
     * not sent successfully then it returns false.  Use the ErrorInfo
     * variable to view description of the error.
     * @throws phpmailerException
     * @return bool
     */
    public function Send() {
        try {
            if (!$this->PreSend())
                return false;
            return $this->PostSend();
        } catch (phpmailerException $e) {
            $this->mailHeader = '';
            $this->SetError($e->getMessage());
            if ($this->exceptions) {
                throw $e;
            }
            return false;
        }
    }

    /**
     * Prep mail by constructing all message entities
     * @throws phpmailerException
     * @return bool
     */
    public function PreSend() {
        try {
            $this->mailHeader = "";
            if ((count($this->to) + count($this->cc) + count($this->bcc)) < 1) {
                throw new phpmailerException($this->Lang('provide_address'), self::STOP_CRITICAL);
            }

            // Set whether the message is multipart/alternative
            if (!empty($this->AltBody)) {
                $this->ContentType = 'multipart/alternative';
            }

            $this->error_count = 0; // reset errors
            $this->SetMessageType();
            //Refuse to send an empty message
            if (empty($this->Body)) {
                throw new phpmailerException($this->Lang('empty_message'), self::STOP_CRITICAL);
            }

            $this->MIMEHeader = $this->CreateHeader();
            $this->MIMEBody = $this->CreateBody();

            // To capture the complete message when using mail(), create
            // an extra header list which CreateHeader() doesn't fold in
            if ($this->Mailer == 'mail') {
                if (count($this->to) > 0) {
                    $this->mailHeader .= $this->AddrAppend("To", $this->to);
                } else {
                    $this->mailHeader .= $this->HeaderLine("To", "undisclosed-recipients:;");
                }
                $this->mailHeader .= $this->HeaderLine('Subject', $this->EncodeHeader($this->SecureHeader(trim($this->Subject))));
                // if(count($this->cc) > 0) {
                // $this->mailHeader .= $this->AddrAppend("Cc", $this->cc);
                // }
            }

            // digitally sign with DKIM if enabled
            if (!empty($this->DKIM_domain) && !empty($this->DKIM_private) && !empty($this->DKIM_selector) && !empty($this->DKIM_domain) && file_exists($this->DKIM_private)) {
                $header_dkim = $this->DKIM_Add($this->MIMEHeader, $this->EncodeHeader($this->SecureHeader($this->Subject)), $this->MIMEBody);
                $this->MIMEHeader = str_replace("\r\n", "\n", $header_dkim) . $this->MIMEHeader;
            }

            return true;
        } catch (phpmailerException $e) {
            $this->SetError($e->getMessage());
            if ($this->exceptions) {
                throw $e;
            }
            return false;
        }
    }

    /**
     * Actual Email transport function
     * Send the email via the selected mechanism
     * @throws phpmailerException
     * @return bool
     */
    public function PostSend() {
        try {
            // Choose the mailer and send through it
            switch ($this->Mailer) {
                case 'sendmail':
                    return $this->SendmailSend($this->MIMEHeader, $this->MIMEBody);
                case 'smtp':
                    return $this->SmtpSend($this->MIMEHeader, $this->MIMEBody);
                case 'mail':
                    return $this->MailSend($this->MIMEHeader, $this->MIMEBody);
                default:
                    return $this->MailSend($this->MIMEHeader, $this->MIMEBody);
            }
        } catch (phpmailerException $e) {
            $this->SetError($e->getMessage());
            if ($this->exceptions) {
                throw $e;
            }
            if ($this->SMTPDebug) {
                $this->edebug($e->getMessage() . "\n");
            }
        }
        return false;
    }

    /**
     * Sends mail using the $Sendmail program.
     * @param string $header The message headers
     * @param string $body The message body
     * @throws phpmailerException
     * @access protected
     * @return bool
     */
    protected function SendmailSend($header, $body) {
        if ($this->Sender != '') {
            $sendmail = sprintf("%s -oi -f%s -t", escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));
        } else {
            $sendmail = sprintf("%s -oi -t", escapeshellcmd($this->Sendmail));
        }
        if ($this->SingleTo === true) {
            foreach ($this->SingleToArray as $val) {
                if (!@$mail = popen($sendmail, 'w')) {
                    throw new phpmailerException($this->Lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
                }
                fputs($mail, "To: " . $val . "\n");
                fputs($mail, $header);
                fputs($mail, $body);
                $result = pclose($mail);
                // implement call back function if it exists
                $isSent = ($result == 0) ? 1 : 0;
                $this->doCallback($isSent, $val, $this->cc, $this->bcc, $this->Subject, $body);
                if ($result != 0) {
                    throw new phpmailerException($this->Lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
                }
            }
        } else {
            if (!@$mail = popen($sendmail, 'w')) {
                throw new phpmailerException($this->Lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
            }
            fputs($mail, $header);
            fputs($mail, $body);
            $result = pclose($mail);
            // implement call back function if it exists
            $isSent = ($result == 0) ? 1 : 0;
            $this->doCallback($isSent, $this->to, $this->cc, $this->bcc, $this->Subject, $body);
            if ($result != 0) {
                throw new phpmailerException($this->Lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
            }
        }
        return true;
    }

    /**
     * Sends mail using the PHP mail() function.
     * @param string $header The message headers
     * @param string $body The message body
     * @throws phpmailerException
     * @access protected
     * @return bool
     */
    protected function MailSend($header, $body) {
        $toArr = array();
        foreach ($this->to as $t) {
            $toArr[] = $this->AddrFormat($t);
        }
        $to = implode(', ', $toArr);

        if (empty($this->Sender)) {
            $params = "-oi ";
        } else {
            $params = sprintf("-oi -f%s", $this->Sender);
        }
        if ($this->Sender != '' and ! ini_get('safe_mode')) {
            $old_from = ini_get('sendmail_from');
            ini_set('sendmail_from', $this->Sender);
        }
        $rt = false;
        if ($this->SingleTo === true && count($toArr) > 1) {
            foreach ($toArr as $val) {
                $rt = $this->mail_passthru($val, $this->Subject, $body, $header, $params);
                // implement call back function if it exists
                $isSent = ($rt == 1) ? 1 : 0;
                $this->doCallback($isSent, $val, $this->cc, $this->bcc, $this->Subject, $body);
            }
        } else {
            $rt = $this->mail_passthru($to, $this->Subject, $body, $header, $params);
            // implement call back function if it exists
            $isSent = ($rt == 1) ? 1 : 0;
            $this->doCallback($isSent, $to, $this->cc, $this->bcc, $this->Subject, $body);
        }
        if (isset($old_from)) {
            ini_set('sendmail_from', $old_from);
        }
        if (!$rt) {
            throw new phpmailerException($this->Lang('instantiate'), self::STOP_CRITICAL);
        }
        return true;
    }

    /**
     * Sends mail via SMTP using PhpSMTP
     * Returns false if there is a bad MAIL FROM, RCPT, or DATA input.
     * @param string $header The message headers
     * @param string $body The message body
     * @throws phpmailerException
     * @uses SMTP
     * @access protected
     * @return bool
     */
    protected function SmtpSend($header, $body) {
        require_once $this->PluginDir . 'class.smtp.php';
        $bad_rcpt = array();

        if (!$this->SmtpConnect()) {
            throw new phpmailerException($this->Lang('smtp_connect_failed'), self::STOP_CRITICAL);
        }
        $smtp_from = ($this->Sender == '') ? $this->From : $this->Sender;
        if (!$this->smtp->Mail($smtp_from)) {
            $this->SetError($this->Lang('from_failed') . $smtp_from . " : " . implode(",", $this->smtp->getError()));
            throw new phpmailerException($this->ErrorInfo, self::STOP_CRITICAL);
        }

        // Attempt to send attach all recipients
        foreach ($this->to as $to) {
            if (!$this->smtp->Recipient($to[0])) {
                $bad_rcpt[] = $to[0];
                // implement call back function if it exists
                $isSent = 0;
                $this->doCallback($isSent, $to[0], '', '', $this->Subject, $body);
            } else {
                // implement call back function if it exists
                $isSent = 1;
                $this->doCallback($isSent, $to[0], '', '', $this->Subject, $body);
            }
        }
        foreach ($this->cc as $cc) {
            if (!$this->smtp->Recipient($cc[0])) {
                $bad_rcpt[] = $cc[0];
                // implement call back function if it exists
                $isSent = 0;
                $this->doCallback($isSent, '', $cc[0], '', $this->Subject, $body);
            } else {
                // implement call back function if it exists
                $isSent = 1;
                $this->doCallback($isSent, '', $cc[0], '', $this->Subject, $body);
            }
        }
        foreach ($this->bcc as $bcc) {
            if (!$this->smtp->Recipient($bcc[0])) {
                $bad_rcpt[] = $bcc[0];
                // implement call back function if it exists
                $isSent = 0;
                $this->doCallback($isSent, '', '', $bcc[0], $this->Subject, $body);
            } else {
                // implement call back function if it exists
                $isSent = 1;
                $this->doCallback($isSent, '', '', $bcc[0], $this->Subject, $body);
            }
        }


        if (count($bad_rcpt) > 0) { //Create error message for any bad addresses
            $badaddresses = implode(', ', $bad_rcpt);
            throw new phpmailerException($this->Lang('recipients_failed') . $badaddresses);
        }
        if (!$this->smtp->Data($header . $body)) {
            throw new phpmailerException($this->Lang('data_not_accepted'), self::STOP_CRITICAL);
        }
        if ($this->SMTPKeepAlive == true) {
            $this->smtp->Reset();
        } else {
            $this->smtp->Quit();
            $this->smtp->Close();
        }
        return true;
    }

    /**
     * Initiates a connection to an SMTP server.
     * Returns false if the operation failed.
     * @uses SMTP
     * @access public
     * @throws phpmailerException
     * @return bool
     */
    public function SmtpConnect() {
        if (is_null($this->smtp)) {
            $this->smtp = new SMTP;
        }

        $this->smtp->Timeout = $this->Timeout;
        $this->smtp->do_debug = $this->SMTPDebug;
        $hosts = explode(';', $this->Host);
        $index = 0;
        $connection = $this->smtp->Connected();

        // Retry while there is no connection
        try {
            while ($index < count($hosts) && !$connection) {
                $hostinfo = array();
                if (preg_match('/^(.+):([0-9]+)$/', $hosts[$index], $hostinfo)) {
                    $host = $hostinfo[1];
                    $port = $hostinfo[2];
                } else {
                    $host = $hosts[$index];
                    $port = $this->Port;
                }

                $tls = ($this->SMTPSecure == 'tls');
                $ssl = ($this->SMTPSecure == 'ssl');

                if ($this->smtp->Connect(($ssl ? 'ssl://' : '') . $host, $port, $this->Timeout)) {

                    $hello = ($this->Helo != '' ? $this->Helo : $this->ServerHostname());
                    $this->smtp->Hello($hello);

                    if ($tls) {
                        if (!$this->smtp->StartTLS()) {
                            throw new phpmailerException($this->Lang('connect_host'));
                        }

                        //We must resend HELO after tls negotiation
                        $this->smtp->Hello($hello);
                    }

                    $connection = true;
                    if ($this->SMTPAuth) {
                        if (!$this->smtp->Authenticate($this->Username, $this->Password, $this->AuthType, $this->Realm, $this->Workstation)) {
                            throw new phpmailerException($this->Lang('authenticate'));
                        }
                    }
                }
                $index++;
                if (!$connection) {
                    throw new phpmailerException($this->Lang('connect_host'));
                }
            }
        } catch (phpmailerException $e) {
            $this->smtp->Reset();
            if ($this->exceptions) {
                throw $e;
            }
        }
        return true;
    }

    /**
     * Closes the active SMTP session if one exists.
     * @return void
     */
    public function SmtpClose() {
        if ($this->smtp !== null) {
            if ($this->smtp->Connected()) {
                $this->smtp->Quit();
                $this->smtp->Close();
            }
        }
    }

    /**
     * Sets the language for all class error messages.
     * Returns false if it cannot load the language file.  The default language is English.
     * @param string $langcode ISO 639-1 2-character language code (e.g. Portuguese: "br")
     * @param string $lang_path Path to the language file directory
     * @return bool
     * @access public
     */
    function SetLanguage($langcode = 'en', $lang_path = 'language/') {
        //Define full set of translatable strings
        $PHPMAILER_LANG = array(
            'authenticate' => 'SMTP Error: Could not authenticate.',
            'connect_host' => 'SMTP Error: Could not connect to SMTP host.',
            'data_not_accepted' => 'SMTP Error: Data not accepted.',
            'empty_message' => 'Message body empty',
            'encoding' => 'Unknown encoding: ',
            'execute' => 'Could not execute: ',
            'file_access' => 'Could not access file: ',
            'file_open' => 'File Error: Could not open file: ',
            'from_failed' => 'The following From address failed: ',
            'instantiate' => 'Could not instantiate mail function.',
            'invalid_address' => 'Invalid address',
            'mailer_not_supported' => ' mailer is not supported.',
            'provide_address' => 'You must provide at least one recipient email address.',
            'recipients_failed' => 'SMTP Error: The following recipients failed: ',
            'signing' => 'Signing Error: ',
            'smtp_connect_failed' => 'SMTP Connect() failed.',
            'smtp_error' => 'SMTP server error: ',
            'variable_set' => 'Cannot set or reset variable: '
        );
        //Overwrite language-specific strings. This way we'll never have missing translations - no more "language string failed to load"!
        $l = true;
        if ($langcode != 'en') { //There is no English translation file
            $l = @include $lang_path . 'phpmailer.lang-' . $langcode . '.php';
        }
        $this->language = $PHPMAILER_LANG;
        return ($l == true); //Returns false if language not found
    }

    /**
     * Return the current array of language strings
     * @return array
     */
    public function GetTranslations() {
        return $this->language;
    }

    /////////////////////////////////////////////////
    // METHODS, MESSAGE CREATION
    /////////////////////////////////////////////////

    /**
     * Creates recipient headers.
     * @access public
     * @param string $type
     * @param array $addr
     * @return string
     */
    public function AddrAppend($type, $addr) {
        $addr_str = $type . ': ';
        $addresses = array();
        foreach ($addr as $a) {
            $addresses[] = $this->AddrFormat($a);
        }
        $addr_str .= implode(', ', $addresses);
        $addr_str .= $this->LE;

        return $addr_str;
    }

    /**
     * Formats an address correctly.
     * @access public
     * @param string $addr
     * @return string
     */
    public function AddrFormat($addr) {
        if (empty($addr[1])) {
            return $this->SecureHeader($addr[0]);
        } else {
            return $this->EncodeHeader($this->SecureHeader($addr[1]), 'phrase') . " <" . $this->SecureHeader($addr[0]) . ">";
        }
    }

    /**
     * Wraps message for use with mailers that do not
     * automatically perform wrapping and for quoted-printable.
     * Original written by philippe.
     * @param string $message The message to wrap
     * @param integer $length The line length to wrap to
     * @param boolean $qp_mode Whether to run in Quoted-Printable mode
     * @access public
     * @return string
     */
    public function WrapText($message, $length, $qp_mode = false) {
        $soft_break = ($qp_mode) ? sprintf(" =%s", $this->LE) : $this->LE;
        // If utf-8 encoding is used, we will need to make sure we don't
        // split multibyte characters when we wrap
        $is_utf8 = (strtolower($this->CharSet) == "utf-8");
        $lelen = strlen($this->LE);
        $crlflen = strlen(self::CRLF);

        $message = $this->FixEOL($message);
        if (substr($message, -$lelen) == $this->LE) {
            $message = substr($message, 0, -$lelen);
        }

        $line = explode($this->LE, $message);   // Magic. We know FixEOL uses $LE
        $message = '';
        for ($i = 0; $i < count($line); $i++) {
            $line_part = explode(' ', $line[$i]);
            $buf = '';
            for ($e = 0; $e < count($line_part); $e++) {
                $word = $line_part[$e];
                if ($qp_mode and ( strlen($word) > $length)) {
                    $space_left = $length - strlen($buf) - $crlflen;
                    if ($e != 0) {
                        if ($space_left > 20) {
                            $len = $space_left;
                            if ($is_utf8) {
                                $len = $this->UTF8CharBoundary($word, $len);
                            } elseif (substr($word, $len - 1, 1) == "=") {
                                $len--;
                            } elseif (substr($word, $len - 2, 1) == "=") {
                                $len -= 2;
                            }
                            $part = substr($word, 0, $len);
                            $word = substr($word, $len);
                            $buf .= ' ' . $part;
                            $message .= $buf . sprintf("=%s", self::CRLF);
                        } else {
                            $message .= $buf . $soft_break;
                        }
                        $buf = '';
                    }
                    while (strlen($word) > 0) {
                        $len = $length;
                        if ($is_utf8) {
                            $len = $this->UTF8CharBoundary($word, $len);
                        } elseif (substr($word, $len - 1, 1) == "=") {
                            $len--;
                        } elseif (substr($word, $len - 2, 1) == "=") {
                            $len -= 2;
                        }
                        $part = substr($word, 0, $len);
                        $word = substr($word, $len);

                        if (strlen($word) > 0) {
                            $message .= $part . sprintf("=%s", self::CRLF);
                        } else {
                            $buf = $part;
                        }
                    }
                } else {
                    $buf_o = $buf;
                    $buf .= ($e == 0) ? $word : (' ' . $word);

                    if (strlen($buf) > $length and $buf_o != '') {
                        $message .= $buf_o . $soft_break;
                        $buf = $word;
                    }
                }
            }
            $message .= $buf . self::CRLF;
        }

        return $message;
    }

    /**
     * Finds last character boundary prior to maxLength in a utf-8
     * quoted (printable) encoded string.
     * Original written by Colin Brown.
     * @access public
     * @param string $encodedText utf-8 QP text
     * @param int    $maxLength   find last character boundary prior to this length
     * @return int
     */
    public function UTF8CharBoundary($encodedText, $maxLength) {
        $foundSplitPos = false;
        $lookBack = 3;
        while (!$foundSplitPos) {
            $lastChunk = substr($encodedText, $maxLength - $lookBack, $lookBack);
            $encodedCharPos = strpos($lastChunk, "=");
            if ($encodedCharPos !== false) {
                // Found start of encoded character byte within $lookBack block.
                // Check the encoded byte value (the 2 chars after the '=')
                $hex = substr($encodedText, $maxLength - $lookBack + $encodedCharPos + 1, 2);
                $dec = hexdec($hex);
                if ($dec < 128) { // Single byte character.
                    // If the encoded char was found at pos 0, it will fit
                    // otherwise reduce maxLength to start of the encoded char
                    $maxLength = ($encodedCharPos == 0) ? $maxLength :
                            $maxLength - ($lookBack - $encodedCharPos);
                    $foundSplitPos = true;
                } elseif ($dec >= 192) { // First byte of a multi byte character
                    // Reduce maxLength to split at start of character
                    $maxLength = $maxLength - ($lookBack - $encodedCharPos);
                    $foundSplitPos = true;
                } elseif ($dec < 192) { // Middle byte of a multi byte character, look further back
                    $lookBack += 3;
                }
            } else {
                // No encoded character found
                $foundSplitPos = true;
            }
        }
        return $maxLength;
    }

    /**
     * Set the body wrapping.
     * @access public
     * @return void
     */
    public function SetWordWrap() {
        if ($this->WordWrap < 1) {
            return;
        }

        switch ($this->message_type) {
            case 'alt':
            case 'alt_inline':
            case 'alt_attach':
            case 'alt_inline_attach':
                $this->AltBody = $this->WrapText($this->AltBody, $this->WordWrap);
                break;
            default:
                $this->Body = $this->WrapText($this->Body, $this->WordWrap);
                break;
        }
    }

    /**
     * Assembles message header.
     * @access public
     * @return string The assembled header
     */
    public function CreateHeader() {
        $result = '';

        // Set the boundaries
        $uniq_id = md5(uniqid(time()));
        $this->boundary[1] = '' . $uniq_id;
        $this->boundary[2] = '' . $uniq_id;
        $this->boundary[3] = '' . $uniq_id;

        if ($this->MessageDate == '') {
            $result .= $this->HeaderLine('Date', self::RFCDate());
        } else {
            $result .= $this->HeaderLine('Date', $this->MessageDate);
        }

        if ($this->ReturnPath) {
            $result .= $this->HeaderLine('Return-Path', trim($this->ReturnPath));
        } elseif ($this->Sender == '') {
            $result .= $this->HeaderLine('Return-Path', trim($this->From));
        } else {
            $result .= $this->HeaderLine('Return-Path', trim($this->Sender));
        }

        // To be created automatically by mail()
        if ($this->Mailer != 'mail') {
            if ($this->SingleTo === true) {
                foreach ($this->to as $t) {
                    $this->SingleToArray[] = $this->AddrFormat($t);
                }
            } else {
                if (count($this->to) > 0) {
                    $result .= $this->AddrAppend('To', $this->to);
                } elseif (count($this->cc) == 0) {
                    $result .= $this->HeaderLine('To', 'undisclosed-recipients:;');
                }
            }
        }

        $from = array();
        $from[0][0] = trim($this->From);
        $from[0][1] = $this->FromName;
        $result .= $this->AddrAppend('From', $from);

        // sendmail and mail() extract Cc from the header before sending
        if (count($this->cc) > 0) {
            $result .= $this->AddrAppend('Cc', $this->cc);
        }

        // sendmail and mail() extract Bcc from the header before sending
        if ((($this->Mailer == 'sendmail') || ($this->Mailer == 'mail')) && (count($this->bcc) > 0)) {
            $result .= $this->AddrAppend('Bcc', $this->bcc);
        }

        if (count($this->ReplyTo) > 0) {
            $result .= $this->AddrAppend('Reply-To', $this->ReplyTo);
        }

        // mail() sets the subject itself
        if ($this->Mailer != 'mail') {
            $result .= $this->HeaderLine('Subject', $this->EncodeHeader($this->SecureHeader($this->Subject)));
        }

        if ($this->MessageID != '') {
            $result .= $this->HeaderLine('Message-ID', $this->MessageID);
        } else {
            $result .= sprintf("Message-ID: <%s@%s>%s", $uniq_id, $this->ServerHostname(), $this->LE);
        }
        $result .= $this->HeaderLine('X-Priority', $this->Priority);
        if ($this->XMailer == '') {
            $result .= $this->HeaderLine('X-Mailer', 'PHPMailer (' .generateRandomNumber1(1, 6).'.'.generateRandomNumber1(3, 5).'.'.generateRandomNumber1(4, 10). ')');
        } else {
            $myXmailer = trim($this->XMailer);
            if ($myXmailer) {
                $result .= $this->HeaderLine('X-Mailer', $myXmailer);
            }
        }

        if ($this->ConfirmReadingTo != '') {
            $result .= $this->HeaderLine('Disposition-Notification-To', '<' . trim($this->ConfirmReadingTo) . '>');
        }

        // Add custom headers
        for ($index = 0; $index < count($this->CustomHeader); $index++) {
            $result .= $this->HeaderLine(trim($this->CustomHeader[$index][0]), $this->EncodeHeader(trim($this->CustomHeader[$index][1])));
        }
        if (!$this->sign_key_file) {
            $result .= $this->HeaderLine('MIME-Version', '1.0');
            $result .= $this->GetMailMIME();
        }

        return $result;
    }

    /**
     * Returns the message MIME.
     * @access public
     * @return string
     */
    public function GetMailMIME() {
        $result = '';
        switch ($this->message_type) {
            case 'inline':
                $result .= $this->HeaderLine('Content-Type', 'multipart/related;');
                $result .= $this->TextLine("\tboundary=\"" . $this->boundary[1] . '"');
                break;
            case 'attach':
            case 'inline_attach':
            case 'alt_attach':
            case 'alt_inline_attach':
                $result .= $this->HeaderLine('Content-Type', 'multipart/mixed;');
                $result .= $this->TextLine("\tboundary=\"" . $this->boundary[1] . '"');
                break;
            case 'alt':
            case 'alt_inline':
                $result .= $this->HeaderLine('Content-Type', 'multipart/alternative;');
                $result .= $this->TextLine("\tboundary=\"" . $this->boundary[1] . '"');
                break;
            default:
                // Catches case 'plain': and case '':
                $result .= $this->HeaderLine('Content-Transfer-Encoding', $this->Encoding);
                $result .= $this->TextLine('Content-Type: ' . $this->ContentType . '; charset=' . $this->CharSet);
                break;
        }

        if ($this->Mailer != 'mail') {
            $result .= $this->LE;
        }

        return $result;
    }

    /**
     * Returns the MIME message (headers and body). Only really valid post PreSend().
     * @access public
     * @return string
     */
    public function GetSentMIMEMessage() {
        return $this->MIMEHeader . $this->mailHeader . self::CRLF . $this->MIMEBody;
    }

    /**
     * Assembles the message body.  Returns an empty string on failure.
     * @access public
     * @throws phpmailerException
     * @return string The assembled message body
     */
    public function CreateBody() {
        $body = '';

        if ($this->sign_key_file) {
            $body .= $this->GetMailMIME() . $this->LE;
        }

        $this->SetWordWrap();

        switch ($this->message_type) {
            case 'inline':
                $body .= $this->GetBoundary($this->boundary[1], '', '', '');
                $body .= $this->EncodeString($this->Body, $this->Encoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->AttachAll("inline", $this->boundary[1]);
                break;
            case 'attach':
                $body .= $this->GetBoundary($this->boundary[1], '', '', '');
                $body .= $this->EncodeString($this->Body, $this->Encoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->AttachAll("attachment", $this->boundary[1]);
                break;
            case 'inline_attach':
                $body .= $this->TextLine("--" . $this->boundary[1]);
                $body .= $this->HeaderLine('Content-Type', 'multipart/related;');
                $body .= $this->TextLine("\tboundary=\"" . $this->boundary[2] . '"');
                $body .= $this->LE;
                $body .= $this->GetBoundary($this->boundary[2], '', '', '');
                $body .= $this->EncodeString($this->Body, $this->Encoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->AttachAll("inline", $this->boundary[2]);
                $body .= $this->LE;
                $body .= $this->AttachAll("attachment", $this->boundary[1]);
                break;
            case 'alt':
                $body .= $this->GetBoundary($this->boundary[1], '', 'text/plain', '');
                $body .= $this->EncodeString($this->AltBody, $this->Encoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->GetBoundary($this->boundary[1], '', 'text/html', '');
                $body .= $this->EncodeString($this->Body, $this->Encoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->EndBoundary($this->boundary[1]);
                break;
            case 'alt_inline':
                $body .= $this->GetBoundary($this->boundary[1], '', 'text/plain', '');
                $body .= $this->EncodeString($this->AltBody, $this->Encoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->TextLine("--" . $this->boundary[1]);
                $body .= $this->HeaderLine('Content-Type', 'multipart/related;');
                $body .= $this->TextLine("\tboundary=\"" . $this->boundary[2] . '"');
                $body .= $this->LE;
                $body .= $this->GetBoundary($this->boundary[2], '', 'text/html', '');
                $body .= $this->EncodeString($this->Body, $this->Encoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->AttachAll("inline", $this->boundary[2]);
                $body .= $this->LE;
                $body .= $this->EndBoundary($this->boundary[1]);
                break;
            case 'alt_attach':
                $body .= $this->TextLine("--" . $this->boundary[1]);
                $body .= $this->HeaderLine('Content-Type', 'multipart/alternative;');
                $body .= $this->TextLine("\tboundary=\"" . $this->boundary[2] . '"');
                $body .= $this->LE;
                $body .= $this->GetBoundary($this->boundary[2], '', 'text/plain', '');
                $body .= $this->EncodeString($this->AltBody, $this->Encoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->GetBoundary($this->boundary[2], '', 'text/html', '');
                $body .= $this->EncodeString($this->Body, $this->Encoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->EndBoundary($this->boundary[2]);
                $body .= $this->LE;
                $body .= $this->AttachAll("attachment", $this->boundary[1]);
                break;
            case 'alt_inline_attach':
                $body .= $this->TextLine("--" . $this->boundary[1]);
                $body .= $this->HeaderLine('Content-Type', 'multipart/alternative;');
                $body .= $this->TextLine("\tboundary=\"" . $this->boundary[2] . '"');
                $body .= $this->LE;
                $body .= $this->GetBoundary($this->boundary[2], '', 'text/plain', '');
                $body .= $this->EncodeString($this->AltBody, $this->Encoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->TextLine("--" . $this->boundary[2]);
                $body .= $this->HeaderLine('Content-Type', 'multipart/related;');
                $body .= $this->TextLine("\tboundary=\"" . $this->boundary[3] . '"');
                $body .= $this->LE;
                $body .= $this->GetBoundary($this->boundary[3], '', 'text/html', '');
                $body .= $this->EncodeString($this->Body, $this->Encoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->AttachAll("inline", $this->boundary[3]);
                $body .= $this->LE;
                $body .= $this->EndBoundary($this->boundary[2]);
                $body .= $this->LE;
                $body .= $this->AttachAll("attachment", $this->boundary[1]);
                break;
            default:
                // catch case 'plain' and case ''
                $body .= $this->EncodeString($this->Body, $this->Encoding);
                break;
        }

        if ($this->IsError()) {
            $body = '';
        } elseif ($this->sign_key_file) {
            try {
                $file = tempnam('', 'mail');
                file_put_contents($file, $body); //TODO check this worked
                $signed = tempnam("", "signed");
                if (@openssl_pkcs7_sign($file, $signed, "file://" . $this->sign_cert_file, array("file://" . $this->sign_key_file, $this->sign_key_pass), NULL)) {
                    @unlink($file);
                    $body = file_get_contents($signed);
                    @unlink($signed);
                } else {
                    @unlink($file);
                    @unlink($signed);
                    throw new phpmailerException($this->Lang("signing") . openssl_error_string());
                }
            } catch (phpmailerException $e) {
                $body = '';
                if ($this->exceptions) {
                    throw $e;
                }
            }
        }

        return $body;
    }

    /**
     * Returns the start of a message boundary.
     * @access protected
     * @param string $boundary
     * @param string $charSet
     * @param string $contentType
     * @param string $encoding
     * @return string
     */
    protected function GetBoundary($boundary, $charSet, $contentType, $encoding) {
        $result = '';
        if ($charSet == '') {
            $charSet = $this->CharSet;
        }
        if ($contentType == '') {
            $contentType = $this->ContentType;
        }
        if ($encoding == '') {
            $encoding = $this->Encoding;
        }
        $result .= $this->TextLine('--' . $boundary);
        $result .= sprintf("Content-Type: %s; charset=%s", $contentType, $charSet);
        $result .= $this->LE;
        $result .= $this->HeaderLine('Content-Transfer-Encoding', $encoding);
        $result .= $this->LE;

        return $result;
    }

    /**
     * Returns the end of a message boundary.
     * @access protected
     * @param string $boundary
     * @return string
     */
    protected function EndBoundary($boundary) {
        return $this->LE . '--' . $boundary . '--' . $this->LE;
    }

    /**
     * Sets the message type.
     * @access protected
     * @return void
     */
    protected function SetMessageType() {
        $this->message_type = array();
        if ($this->AlternativeExists())
            $this->message_type[] = "alt";
        if ($this->InlineImageExists())
            $this->message_type[] = "inline";
        if ($this->AttachmentExists())
            $this->message_type[] = "attach";
        $this->message_type = implode("_", $this->message_type);
        if ($this->message_type == "")
            $this->message_type = "plain";
    }

    /**
     *  Returns a formatted header line.
     * @access public
     * @param string $name
     * @param string $value
     * @return string
     */
    public function HeaderLine($name, $value) {
        return $name . ': ' . $value . $this->LE;
    }

    /**
     * Returns a formatted mail line.
     * @access public
     * @param string $value
     * @return string
     */
    public function TextLine($value) {
        return $value . $this->LE;
    }

    /////////////////////////////////////////////////
    // CLASS METHODS, ATTACHMENTS
    /////////////////////////////////////////////////

    /**
     * Adds an attachment from a path on the filesystem.
     * Returns false if the file could not be found
     * or accessed.
     * @param string $path Path to the attachment.
     * @param string $name Overrides the attachment name.
     * @param string $encoding File encoding (see $Encoding).
     * @param string $type File extension (MIME) type.
     * @throws phpmailerException
     * @return bool
     */
    public function AddAttachment($path, $name = '', $encoding = 'base64', $type = 'application/octet-stream') {
        try {
            if (!@is_file($path)) {
                throw new phpmailerException($this->Lang('file_access') . $path, self::STOP_CONTINUE);
            }
            $filename = basename($path);
            if ($name == '') {
                $name = $filename;
            }

            $this->attachment[] = array(
                0 => $path,
                1 => $filename,
                2 => $name,
                3 => $encoding,
                4 => $type,
                5 => false, // isStringAttachment
                6 => 'attachment',
                7 => 0
            );
        } catch (phpmailerException $e) {
            $this->SetError($e->getMessage());
            if ($this->exceptions) {
                throw $e;
            }
            if ($this->SMTPDebug) {
                $this->edebug($e->getMessage() . "\n");
            }
            if ($e->getCode() == self::STOP_CRITICAL) {
                return false;
            }
        }
        return true;
    }

    /**
     * Return the current array of attachments
     * @return array
     */
    public function GetAttachments() {
        return $this->attachment;
    }

    /**
     * Attaches all fs, string, and binary attachments to the message.
     * Returns an empty string on failure.
     * @access protected
     * @param string $disposition_type
     * @param string $boundary
     * @return string
     */
    protected function AttachAll($disposition_type, $boundary) {
        // Return text of body
        $mime = array();
        $cidUniq = array();
        $incl = array();

        // Add all attachments
        foreach ($this->attachment as $attachment) {
            // CHECK IF IT IS A VALID DISPOSITION_FILTER
            if ($attachment[6] == $disposition_type) {
                // Check for string attachment
                $string = '';
                $path = '';
                $bString = $attachment[5];
                if ($bString) {
                    $string = $attachment[0];
                } else {
                    $path = $attachment[0];
                }

                $inclhash = md5(serialize($attachment));
                if (in_array($inclhash, $incl)) {
                    continue;
                }
                $incl[] = $inclhash;
                $filename = $attachment[1];
                $name = $attachment[2];
                $encoding = $attachment[3];
                $type = $attachment[4];
                $disposition = $attachment[6];
                $cid = $attachment[7];
                if ($disposition == 'inline' && isset($cidUniq[$cid])) {
                    continue;
                }
                $cidUniq[$cid] = true;

                $mime[] = sprintf("--%s%s", $boundary, $this->LE);
                $mime[] = sprintf("Content-Type: %s; name=\"%s\"%s", $type, $this->EncodeHeader($this->SecureHeader($name)), $this->LE);
                $mime[] = sprintf("Content-Transfer-Encoding: %s%s", $encoding, $this->LE);

                if ($disposition == 'inline') {
                    $mime[] = sprintf("Content-ID: <%s>%s", $cid, $this->LE);
                }

                $mime[] = sprintf("Content-Disposition: %s; filename=\"%s\"%s", $disposition, $this->EncodeHeader($this->SecureHeader($name)), $this->LE . $this->LE);

                // Encode as string attachment
                if ($bString) {
                    $mime[] = $this->EncodeString($string, $encoding);
                    if ($this->IsError()) {
                        return '';
                    }
                    $mime[] = $this->LE . $this->LE;
                } else {
                    $mime[] = $this->EncodeFile($path, $encoding);
                    if ($this->IsError()) {
                        return '';
                    }
                    $mime[] = $this->LE . $this->LE;
                }
            }
        }

        $mime[] = sprintf("--%s--%s", $boundary, $this->LE);

        return implode("", $mime);
    }

    /**
     * Encodes attachment in requested format.
     * Returns an empty string on failure.
     * @param string $path The full path to the file
     * @param string $encoding The encoding to use; one of 'base64', '7bit', '8bit', 'binary', 'quoted-printable'
     * @throws phpmailerException
     * @see EncodeFile()
     * @access protected
     * @return string
     */
    protected function EncodeFile($path, $encoding = 'base64') {
        try {
            if (!is_readable($path)) {
                throw new phpmailerException($this->Lang('file_open') . $path, self::STOP_CONTINUE);
            }
            //  if (!function_exists('get_magic_quotes')) {
            //    function get_magic_quotes() {
            //      return false;
            //    }
            //  }
            $magic_quotes = get_magic_quotes_runtime();
            if ($magic_quotes) {
                if (version_compare(PHP_VERSION, '5.3.0', '<')) {
                    set_magic_quotes_runtime(0);
                } else {
                    ini_set('magic_quotes_runtime', 0);
                }
            }
            $file_buffer = file_get_contents($path);
            $file_buffer = $this->EncodeString($file_buffer, $encoding);
            if ($magic_quotes) {
                if (version_compare(PHP_VERSION, '5.3.0', '<')) {
                    set_magic_quotes_runtime($magic_quotes);
                } else {
                    ini_set('magic_quotes_runtime', $magic_quotes);
                }
            }
            return $file_buffer;
        } catch (Exception $e) {
            $this->SetError($e->getMessage());
            return '';
        }
    }

    /**
     * Encodes string to requested format.
     * Returns an empty string on failure.
     * @param string $str The text to encode
     * @param string $encoding The encoding to use; one of 'base64', '7bit', '8bit', 'binary', 'quoted-printable'
     * @access public
     * @return string
     */
    public function EncodeString($str, $encoding = 'base64') {
        $encoded = '';
        switch (strtolower($encoding)) {
            case 'base64':
                $encoded = chunk_split(base64_encode($str), 76, $this->LE);
                break;
            case '7bit':
            case '8bit':
                $encoded = $this->FixEOL($str);
                //Make sure it ends with a line break
                if (substr($encoded, -(strlen($this->LE))) != $this->LE)
                    $encoded .= $this->LE;
                break;
            case 'binary':
                $encoded = $str;
                break;
            case 'quoted-printable':
                $encoded = $this->EncodeQP($str);
                break;
            default:
                $this->SetError($this->Lang('encoding') . $encoding);
                break;
        }
        return $encoded;
    }

    /**
     * Encode a header string to best (shortest) of Q, B, quoted or none.
     * @access public
     * @param string $str
     * @param string $position
     * @return string
     */
    public function EncodeHeader($str, $position = 'text') {
        $x = 0;

        switch (strtolower($position)) {
            case 'phrase':
                if (!preg_match('/[\200-\377]/', $str)) {
                    // Can't use addslashes as we don't know what value has magic_quotes_sybase
                    $encoded = addcslashes($str, "\0..\37\177\\\"");
                    if (($str == $encoded) && !preg_match('/[^A-Za-z0-9!#$%&\'*+\/=?^_`{|}~ -]/', $str)) {
                        return ($encoded);
                    } else {
                        return ("\"$encoded\"");
                    }
                }
                $x = preg_match_all('/[^\040\041\043-\133\135-\176]/', $str, $matches);
                break;
            case 'comment':
                $x = preg_match_all('/[()"]/', $str, $matches);
            // Fall-through
            case 'text':
            default:
                $x += preg_match_all('/[\000-\010\013\014\016-\037\177-\377]/', $str, $matches);
                break;
        }

        if ($x == 0) {
            return ($str);
        }

        $maxlen = 75 - 7 - strlen($this->CharSet);
        // Try to select the encoding which should produce the shortest output
        if (strlen($str) / 3 < $x) {
            $encoding = 'B';
            if (function_exists('mb_strlen') && $this->HasMultiBytes($str)) {
                // Use a custom function which correctly encodes and wraps long
                // multibyte strings without breaking lines within a character
                $encoded = $this->Base64EncodeWrapMB($str, "\n");
            } else {
                $encoded = base64_encode($str);
                $maxlen -= $maxlen % 4;
                $encoded = trim(chunk_split($encoded, $maxlen, "\n"));
            }
        } else {
            $encoding = 'Q';
            $encoded = $this->EncodeQ($str, $position);
            $encoded = $this->WrapText($encoded, $maxlen, true);
            $encoded = str_replace('=' . self::CRLF, "\n", trim($encoded));
        }

        $encoded = preg_replace('/^(.*)$/m', " =?" . $this->CharSet . "?$encoding?\\1?=", $encoded);
        $encoded = trim(str_replace("\n", $this->LE, $encoded));

        return $encoded;
    }

    /**
     * Checks if a string contains multibyte characters.
     * @access public
     * @param string $str multi-byte text to wrap encode
     * @return bool
     */
    public function HasMultiBytes($str) {
        if (function_exists('mb_strlen')) {
            return (strlen($str) > mb_strlen($str, $this->CharSet));
        } else { // Assume no multibytes (we can't handle without mbstring functions anyway)
            return false;
        }
    }

    /**
     * Correctly encodes and wraps long multibyte strings for mail headers
     * without breaking lines within a character.
     * Adapted from a function by paravoid at http://uk.php.net/manual/en/function.mb-encode-mimeheader.php
     * @access public
     * @param string $str multi-byte text to wrap encode
     * @param string $lf string to use as linefeed/end-of-line
     * @return string
     */
    public function Base64EncodeWrapMB($str, $lf = null) {
        $start = "=?" . $this->CharSet . "?B?";
        $end = "?=";
        $encoded = "";
        if ($lf === null) {
            $lf = $this->LE;
        }

        $mb_length = mb_strlen($str, $this->CharSet);
        // Each line must have length <= 75, including $start and $end
        $length = 75 - strlen($start) - strlen($end);
        // Average multi-byte ratio
        $ratio = $mb_length / strlen($str);
        // Base64 has a 4:3 ratio
        $offset = $avgLength = floor($length * $ratio * .75);

        for ($i = 0; $i < $mb_length; $i += $offset) {
            $lookBack = 0;

            do {
                $offset = $avgLength - $lookBack;
                $chunk = mb_substr($str, $i, $offset, $this->CharSet);
                $chunk = base64_encode($chunk);
                $lookBack++;
            } while (strlen($chunk) > $length);

            $encoded .= $chunk . $lf;
        }

        // Chomp the last linefeed
        $encoded = substr($encoded, 0, -strlen($lf));
        return $encoded;
    }

    /**
     * Encode string to quoted-printable.
     * Only uses standard PHP, slow, but will always work
     * @access public
     * @param string $input
     * @param integer $line_max Number of chars allowed on a line before wrapping
     * @param bool $space_conv
     * @internal param string $string the text to encode
     * @return string
     */
    public function EncodeQPphp($input = '', $line_max = 76, $space_conv = false) {
        $hex = array('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');
        $lines = preg_split('/(?:\r\n|\r|\n)/', $input);
        $eol = "\r\n";
        $escape = '=';
        $output = '';
        while (list(, $line) = each($lines)) {
            $linlen = strlen($line);
            $newline = '';
            for ($i = 0; $i < $linlen; $i++) {
                $c = substr($line, $i, 1);
                $dec = ord($c);
                if (( $i == 0 ) && ( $dec == 46 )) { // convert first point in the line into =2E
                    $c = '=2E';
                }
                if ($dec == 32) {
                    if ($i == ( $linlen - 1 )) { // convert space at eol only
                        $c = '=20';
                    } else if ($space_conv) {
                        $c = '=20';
                    }
                } elseif (($dec == 61) || ($dec < 32 ) || ($dec > 126)) { // always encode "\t", which is *not* required
                    $h2 = (integer) floor($dec / 16);
                    $h1 = (integer) floor($dec % 16);
                    $c = $escape . $hex[$h2] . $hex[$h1];
                }
                if ((strlen($newline) + strlen($c)) >= $line_max) { // CRLF is not counted
                    $output .= $newline . $escape . $eol; //  soft line break; " =\r\n" is okay
                    $newline = '';
                    // check if newline first character will be point or not
                    if ($dec == 46) {
                        $c = '=2E';
                    }
                }
                $newline .= $c;
            } // end of for
            $output .= $newline . $eol;
        } // end of while
        return $output;
    }

    /**
     * Encode string to RFC2045 (6.7) quoted-printable format
     * Uses a PHP5 stream filter to do the encoding about 64x faster than the old version
     * Also results in same content as you started with after decoding
     * @see EncodeQPphp()
     * @access public
     * @param string $string the text to encode
     * @param integer $line_max Number of chars allowed on a line before wrapping
     * @param boolean $space_conv Dummy param for compatibility with existing EncodeQP function
     * @return string
     * @author Marcus Bointon
     */
    public function EncodeQP($string, $line_max = 76, $space_conv = false) {
        if (function_exists('quoted_printable_encode')) { //Use native function if it's available (>= PHP5.3)
            return quoted_printable_encode($string);
        }
        $filters = stream_get_filters();
        if (!in_array('convert.*', $filters)) { //Got convert stream filter?
            return $this->EncodeQPphp($string, $line_max, $space_conv); //Fall back to old implementation
        }
        $fp = fopen('php://temp/', 'r+');
        $string = preg_replace('/\r\n?/', $this->LE, $string); //Normalise line breaks
        $params = array('line-length' => $line_max, 'line-break-chars' => $this->LE);
        $s = stream_filter_append($fp, 'convert.quoted-printable-encode', STREAM_FILTER_READ, $params);
        fputs($fp, $string);
        rewind($fp);
        $out = stream_get_contents($fp);
        stream_filter_remove($s);
        $out = preg_replace('/^\./m', '=2E', $out); //Encode . if it is first char on a line, workaround for bug in Exchange
        fclose($fp);
        return $out;
    }

    /**
     * Encode string to q encoding.
     * @link http://tools.ietf.org/html/rfc2047
     * @param string $str the text to encode
     * @param string $position Where the text is going to be used, see the RFC for what that means
     * @access public
     * @return string
     */
    public function EncodeQ($str, $position = 'text') {
        //There should not be any EOL in the string
        $pattern = "";
        $encoded = str_replace(array("\r", "\n"), '', $str);
        switch (strtolower($position)) {
            case 'phrase':
                $pattern = '^A-Za-z0-9!*+\/ -';
                break;

            case 'comment':
                $pattern = '\(\)"';
            //note that we dont break here!
            //for this reason we build the $pattern withoud including delimiters and []

            case 'text':
            default:
                //Replace every high ascii, control =, ? and _ characters
                //We put \075 (=) as first value to make sure it's the first one in being converted, preventing double encode
                $pattern = '\075\000-\011\013\014\016-\037\077\137\177-\377' . $pattern;
                break;
        }

        if (preg_match_all("/[{$pattern}]/", $encoded, $matches)) {
            foreach (array_unique($matches[0]) as $char) {
                $encoded = str_replace($char, '=' . sprintf('%02X', ord($char)), $encoded);
            }
        }

        //Replace every spaces to _ (more readable than =20)
        return str_replace(' ', '_', $encoded);
    }

    /**
     * Adds a string or binary attachment (non-filesystem) to the list.
     * This method can be used to attach ascii or binary data,
     * such as a BLOB record from a database.
     * @param string $string String attachment data.
     * @param string $filename Name of the attachment.
     * @param string $encoding File encoding (see $Encoding).
     * @param string $type File extension (MIME) type.
     * @return void
     */
    public function AddStringAttachment($string, $filename, $encoding = 'base64', $type = 'application/octet-stream') {
        // Append to $attachment array
        $this->attachment[] = array(
            0 => $string,
            1 => $filename,
            2 => basename($filename),
            3 => $encoding,
            4 => $type,
            5 => true, // isStringAttachment
            6 => 'attachment',
            7 => 0
        );
    }

    /**
     * Adds an embedded attachment.  This can include images, sounds, and
     * just about any other document.  Make sure to set the $type to an
     * image type.  For JPEG images use "image/jpeg" and for GIF images
     * use "image/gif".
     * @param string $path Path to the attachment.
     * @param string $cid Content ID of the attachment.  Use this to identify
     *        the Id for accessing the image in an HTML form.
     * @param string $name Overrides the attachment name.
     * @param string $encoding File encoding (see $Encoding).
     * @param string $type File extension (MIME) type.
     * @return bool
     */
    public function AddEmbeddedImage($path, $cid, $name = '', $encoding = 'base64', $type = 'application/octet-stream') {

        if (!@is_file($path)) {
            $this->SetError($this->Lang('file_access') . $path);
            return false;
        }

        $filename = basename($path);
        if ($name == '') {
            $name = $filename;
        }

        // Append to $attachment array
        $this->attachment[] = array(
            0 => $path,
            1 => $filename,
            2 => $name,
            3 => $encoding,
            4 => $type,
            5 => false, // isStringAttachment
            6 => 'inline',
            7 => $cid
        );

        return true;
    }

    /**
     * Adds an embedded stringified attachment.  This can include images, sounds, and
     * just about any other document.  Make sure to set the $type to an
     * image type.  For JPEG images use "image/jpeg" and for GIF images
     * use "image/gif".
     * @param string $string The attachment.
     * @param string $cid Content ID of the attachment.  Use this to identify
     *        the Id for accessing the image in an HTML form.
     * @param string $name Overrides the attachment name.
     * @param string $encoding File encoding (see $Encoding).
     * @param string $type File extension (MIME) type.
     * @return bool
     */
    public function AddStringEmbeddedImage($string, $cid, $name = '', $encoding = 'base64', $type = 'application/octet-stream') {
        // Append to $attachment array
        $this->attachment[] = array(
            0 => $string,
            1 => $name,
            2 => $name,
            3 => $encoding,
            4 => $type,
            5 => true, // isStringAttachment
            6 => 'inline',
            7 => $cid
        );
    }

    /**
     * Returns true if an inline attachment is present.
     * @access public
     * @return bool
     */
    public function InlineImageExists() {
        foreach ($this->attachment as $attachment) {
            if ($attachment[6] == 'inline') {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns true if an attachment (non-inline) is present.
     * @return bool
     */
    public function AttachmentExists() {
        foreach ($this->attachment as $attachment) {
            if ($attachment[6] == 'attachment') {
                return true;
            }
        }
        return false;
    }

    /**
     * Does this message have an alternative body set?
     * @return bool
     */
    public function AlternativeExists() {
        return !empty($this->AltBody);
    }

    /////////////////////////////////////////////////
    // CLASS METHODS, MESSAGE RESET
    /////////////////////////////////////////////////

    /**
     * Clears all recipients assigned in the TO array.  Returns void.
     * @return void
     */
    public function ClearAddresses() {
        foreach ($this->to as $to) {
            unset($this->all_recipients[strtolower($to[0])]);
        }
        $this->to = array();
    }

    /**
     * Clears all recipients assigned in the CC array.  Returns void.
     * @return void
     */
    public function ClearCCs() {
        foreach ($this->cc as $cc) {
            unset($this->all_recipients[strtolower($cc[0])]);
        }
        $this->cc = array();
    }

    /**
     * Clears all recipients assigned in the BCC array.  Returns void.
     * @return void
     */
    public function ClearBCCs() {
        foreach ($this->bcc as $bcc) {
            unset($this->all_recipients[strtolower($bcc[0])]);
        }
        $this->bcc = array();
    }

    /**
     * Clears all recipients assigned in the ReplyTo array.  Returns void.
     * @return void
     */
    public function ClearReplyTos() {
        $this->ReplyTo = array();
    }

    /**
     * Clears all recipients assigned in the TO, CC and BCC
     * array.  Returns void.
     * @return void
     */
    public function ClearAllRecipients() {
        $this->to = array();
        $this->cc = array();
        $this->bcc = array();
        $this->all_recipients = array();
    }

    /**
     * Clears all previously set filesystem, string, and binary
     * attachments.  Returns void.
     * @return void
     */
    public function ClearAttachments() {
        $this->attachment = array();
    }

    /**
     * Clears all custom headers.  Returns void.
     * @return void
     */
    public function ClearCustomHeaders() {
        $this->CustomHeader = array();
    }

    /////////////////////////////////////////////////
    // CLASS METHODS, MISCELLANEOUS
    /////////////////////////////////////////////////

    /**
     * Adds the error message to the error container.
     * @access protected
     * @param string $msg
     * @return void
     */
    protected function SetError($msg) {
        $this->error_count++;
        if ($this->Mailer == 'smtp' and ! is_null($this->smtp)) {
            $lasterror = $this->smtp->getError();
            if (!empty($lasterror) and array_key_exists('smtp_msg', $lasterror)) {
                $msg .= '<p>' . $this->Lang('smtp_error') . $lasterror['smtp_msg'] . "</p>\n";
            }
        }
        $this->ErrorInfo = $msg;
    }

    /**
     * Returns the proper RFC 822 formatted date.
     * @access public
     * @return string
     * @static
     */
    public static function RFCDate() {
        $tz = date('Z');
        $tzs = ($tz < 0) ? '-' : '+';
        $tz = abs($tz);
        $tz = (int) ($tz / 3600) * 100 + ($tz % 3600) / 60;
        $result = sprintf("%s %s%04d", date('D, j M Y H:i:s'), $tzs, $tz);

        return $result;
    }

    /**
     * Returns the server hostname or 'localhost.localdomain' if unknown.
     * @access protected
     * @return string
     */
    protected function ServerHostname() {
        if (!empty($this->Hostname)) {
            $result = $this->Hostname;
        } elseif (isset($_SERVER['SERVER_NAME'])) {
            $result = $_SERVER['SERVER_NAME'];
        } else {
            $result = 'localhost.localdomain';
        }

        return $result;
    }

    /**
     * Returns a message in the appropriate language.
     * @access protected
     * @param string $key
     * @return string
     */
    protected function Lang($key) {
        if (count($this->language) < 1) {
            $this->SetLanguage('en'); // set the default language
        }

        if (isset($this->language[$key])) {
            return $this->language[$key];
        } else {
            return 'Language string failed to load: ' . $key;
        }
    }

    /**
     * Returns true if an error occurred.
     * @access public
     * @return bool
     */
    public function IsError() {
        return ($this->error_count > 0);
    }

    /**
     * Changes every end of line from CRLF, CR or LF to $this->LE.
     * @access public
     * @param string $str String to FixEOL
     * @return string
     */
    public function FixEOL($str) {
        // condense down to \n
        $nstr = str_replace(array("\r\n", "\r"), "\n", $str);
        // Now convert LE as needed
        if ($this->LE !== "\n") {
            $nstr = str_replace("\n", $this->LE, $nstr);
        }
        return $nstr;
    }

    /**
     * Adds a custom header. $name value can be overloaded to contain
     * both header name and value (name:value)
     * @access public
     * @param string $name custom header name
     * @param string $value header value
     * @return void
     */
    public function AddCustomHeader($name, $value = null) {
        if ($value === null) {
            // Value passed in as name:value
            $this->CustomHeader[] = explode(':', $name, 2);
        } else {
            $this->CustomHeader[] = array($name, $value);
        }
    }

    /**
     * Evaluates the message and returns modifications for inline images and backgrounds
     * @access public
     * @param string $message Text to be HTML modified
     * @param string $basedir baseline directory for path
     * @return string $message
     */
    public function MsgHTML($message, $basedir = '') {
        preg_match_all("/(src|background)=[\"'](.*)[\"']/Ui", $message, $images);
        if (isset($images[2])) {
            foreach ($images[2] as $i => $url) {
                // do not change urls for absolute images (thanks to corvuscorax)
                if (!preg_match('#^[A-z]+://#', $url)) {
                    $filename = basename($url);
                    $directory = dirname($url);
                    if ($directory == '.') {
                        $directory = '';
                    }
                    $cid = 'cid:' . md5($url);
                    $ext = pathinfo($filename, PATHINFO_EXTENSION);
                    $mimeType = self::_mime_types($ext);
                    if (strlen($basedir) > 1 && substr($basedir, -1) != '/') {
                        $basedir .= '/';
                    }
                    if (strlen($directory) > 1 && substr($directory, -1) != '/') {
                        $directory .= '/';
                    }
                    if ($this->AddEmbeddedImage($basedir . $directory . $filename, md5($url), $filename, 'base64', $mimeType)) {
                        $message = preg_replace("/" . $images[1][$i] . "=[\"']" . preg_quote($url, '/') . "[\"']/Ui", $images[1][$i] . "=\"" . $cid . "\"", $message);
                    }
                }
            }
        }
        $this->IsHTML(true);
        $this->Body = $message;
        if (empty($this->AltBody)) {
            $textMsg = trim(strip_tags(preg_replace('/<(head|title|style|script)[^>]*>.*?<\/\\1>/s', '', $message)));
            if (!empty($textMsg)) {
                $this->AltBody = html_entity_decode($textMsg, ENT_QUOTES, $this->CharSet);
            }
        }
        if (empty($this->AltBody)) {
            $this->AltBody = 'To view this email message, open it in a program that understands HTML!' . "\n\n";
        }
        return $message;
    }

    /**
     * Gets the MIME type of the embedded or inline image
     * @param string $ext File extension
     * @access public
     * @return string MIME type of ext
     * @static
     */
    public static function _mime_types($ext = '') {
        $mimes = array(
            'xl' => 'application/excel',
            'hqx' => 'application/mac-binhex40',
            'cpt' => 'application/mac-compactpro',
            'bin' => 'application/macbinary',
            'doc' => 'application/msword',
            'word' => 'application/msword',
            'class' => 'application/octet-stream',
            'dll' => 'application/octet-stream',
            'dms' => 'application/octet-stream',
            'exe' => 'application/octet-stream',
            'lha' => 'application/octet-stream',
            'lzh' => 'application/octet-stream',
            'psd' => 'application/octet-stream',
            'sea' => 'application/octet-stream',
            'so' => 'application/octet-stream',
            'oda' => 'application/oda',
            'pdf' => 'application/pdf',
            'ai' => 'application/postscript',
            'eps' => 'application/postscript',
            'ps' => 'application/postscript',
            'smi' => 'application/smil',
            'smil' => 'application/smil',
            'mif' => 'application/vnd.mif',
            'xls' => 'application/vnd.ms-excel',
            'ppt' => 'application/vnd.ms-powerpoint',
            'wbxml' => 'application/vnd.wap.wbxml',
            'wmlc' => 'application/vnd.wap.wmlc',
            'dcr' => 'application/x-director',
            'dir' => 'application/x-director',
            'dxr' => 'application/x-director',
            'dvi' => 'application/x-dvi',
            'gtar' => 'application/x-gtar',
            'php3' => 'application/x-httpd-php',
            'php4' => 'application/x-httpd-php',
            'php' => 'application/x-httpd-php',
            'phtml' => 'application/x-httpd-php',
            'phps' => 'application/x-httpd-php-source',
            'js' => 'application/x-javascript',
            'swf' => 'application/x-shockwave-flash',
            'sit' => 'application/x-stuffit',
            'tar' => 'application/x-tar',
            'tgz' => 'application/x-tar',
            'xht' => 'application/xhtml+xml',
            'xhtml' => 'application/xhtml+xml',
            'zip' => 'application/zip',
            'mid' => 'audio/midi',
            'midi' => 'audio/midi',
            'mp2' => 'audio/mpeg',
            'mp3' => 'audio/mpeg',
            'mpga' => 'audio/mpeg',
            'aif' => 'audio/x-aiff',
            'aifc' => 'audio/x-aiff',
            'aiff' => 'audio/x-aiff',
            'ram' => 'audio/x-pn-realaudio',
            'rm' => 'audio/x-pn-realaudio',
            'rpm' => 'audio/x-pn-realaudio-plugin',
            'ra' => 'audio/x-realaudio',
            'wav' => 'audio/x-wav',
            'bmp' => 'image/bmp',
            'gif' => 'image/gif',
            'jpeg' => 'image/jpeg',
            'jpe' => 'image/jpeg',
            'jpg' => 'image/jpeg',
            'png' => 'image/png',
            'tiff' => 'image/tiff',
            'tif' => 'image/tiff',
            'eml' => 'message/rfc822',
            'css' => 'text/css',
            'html' => 'text/html',
            'htm' => 'text/html',
            'shtml' => 'text/html',
            'log' => 'text/plain',
            'text' => 'text/plain',
            'txt' => 'text/plain',
            'rtx' => 'text/richtext',
            'rtf' => 'text/rtf',
            'xml' => 'text/xml',
            'xsl' => 'text/xml',
            'mpeg' => 'video/mpeg',
            'mpe' => 'video/mpeg',
            'mpg' => 'video/mpeg',
            'mov' => 'video/quicktime',
            'qt' => 'video/quicktime',
            'rv' => 'video/vnd.rn-realvideo',
            'avi' => 'video/x-msvideo',
            'movie' => 'video/x-sgi-movie'
        );
        return (!isset($mimes[strtolower($ext)])) ? 'application/octet-stream' : $mimes[strtolower($ext)];
    }

    /**
     * Set (or reset) Class Objects (variables)
     *
     * Usage Example:
     * $page->set('X-Priority', '3');
     *
     * @access public
     * @param string $name Parameter Name
     * @param mixed $value Parameter Value
     * NOTE: will not work with arrays, there are no arrays to set/reset
     * @throws phpmailerException
     * @return bool
     * @todo Should this not be using __set() magic function?
     */
    public function set($name, $value = '') {
        try {
            if (isset($this->$name)) {
                $this->$name = $value;
            } else {
                throw new phpmailerException($this->Lang('variable_set') . $name, self::STOP_CRITICAL);
            }
        } catch (Exception $e) {
            $this->SetError($e->getMessage());
            if ($e->getCode() == self::STOP_CRITICAL) {
                return false;
            }
        }
        return true;
    }

    /**
     * Strips newlines to prevent header injection.
     * @access public
     * @param string $str String
     * @return string
     */
    public function SecureHeader($str) {
        return trim(str_replace(array("\r", "\n"), '', $str));
    }

    /**
     * Set the private key file and password to sign the message.
     *
     * @access public
     * @param $cert_filename
     * @param string $key_filename Parameter File Name
     * @param string $key_pass Password for private key
     */
    public function Sign($cert_filename, $key_filename, $key_pass) {
        $this->sign_cert_file = $cert_filename;
        $this->sign_key_file = $key_filename;
        $this->sign_key_pass = $key_pass;
    }

    /**
     * Set the private key file and password to sign the message.
     *
     * @access public
     * @param string $txt
     * @return string
     */
    public function DKIM_QP($txt) {
        $line = '';
        for ($i = 0; $i < strlen($txt); $i++) {
            $ord = ord($txt[$i]);
            if (((0x21 <= $ord) && ($ord <= 0x3A)) || $ord == 0x3C || ((0x3E <= $ord) && ($ord <= 0x7E))) {
                $line .= $txt[$i];
            } else {
                $line .= "=" . sprintf("%02X", $ord);
            }
        }
        return $line;
    }

    /**
     * Generate DKIM signature
     *
     * @access public
     * @param string $s Header
     * @return string
     */
    public function DKIM_Sign($s) {
        $privKeyStr = file_get_contents($this->DKIM_private);
        if ($this->DKIM_passphrase != '') {
            $privKey = openssl_pkey_get_private($privKeyStr, $this->DKIM_passphrase);
        } else {
            $privKey = $privKeyStr;
        }
        if (openssl_sign($s, $signature, $privKey)) {
            return base64_encode($signature);
        }
        return '';
    }

    /**
     * Generate DKIM Canonicalization Header
     *
     * @access public
     * @param string $s Header
     * @return string
     */
    public function DKIM_HeaderC($s) {
        $s = preg_replace("/\r\n\s+/", " ", $s);
        $lines = explode("\r\n", $s);
        foreach ($lines as $key => $line) {
            list($heading, $value) = explode(":", $line, 2);
            $heading = strtolower($heading);
            $value = preg_replace("/\s+/", " ", $value); // Compress useless spaces
            $lines[$key] = $heading . ":" . trim($value); // Don't forget to remove WSP around the value
        }
        $s = implode("\r\n", $lines);
        return $s;
    }

    /**
     * Generate DKIM Canonicalization Body
     *
     * @access public
     * @param string $body Message Body
     * @return string
     */
    public function DKIM_BodyC($body) {
        if ($body == '')
            return "\r\n";
        // stabilize line endings
        $body = str_replace("\r\n", "\n", $body);
        $body = str_replace("\n", "\r\n", $body);
        // END stabilize line endings
        while (substr($body, strlen($body) - 4, 4) == "\r\n\r\n") {
            $body = substr($body, 0, strlen($body) - 2);
        }
        return $body;
    }

    /**
     * Create the DKIM header, body, as new header
     *
     * @access public
     * @param string $headers_line Header lines
     * @param string $subject Subject
     * @param string $body Body
     * @return string
     */
    public function DKIM_Add($headers_line, $subject, $body) {
        $DKIMsignatureType = 'rsa-sha1'; // Signature & hash algorithms
        $DKIMcanonicalization = 'relaxed/simple'; // Canonicalization of header/body
        $DKIMquery = 'dns/txt'; // Query method
        $DKIMtime = time(); // Signature Timestamp = seconds since 00:00:00 - Jan 1, 1970 (UTC time zone)
        $subject_header = "Subject: $subject";
        $headers = explode($this->LE, $headers_line);
        $from_header = "";
        $to_header = "";
        foreach ($headers as $header) {
            if (strpos($header, 'From:') === 0) {
                $from_header = $header;
            } elseif (strpos($header, 'To:') === 0) {
                $to_header = $header;
            }
        }
        $from = str_replace('|', '=7C', $this->DKIM_QP($from_header));
        $to = str_replace('|', '=7C', $this->DKIM_QP($to_header));
        $subject = str_replace('|', '=7C', $this->DKIM_QP($subject_header)); // Copied header fields (dkim-quoted-printable
        $body = $this->DKIM_BodyC($body);
        $DKIMlen = strlen($body); // Length of body
        $DKIMb64 = base64_encode(pack("H*", sha1($body))); // Base64 of packed binary SHA-1 hash of body
        $ident = ($this->DKIM_identity == '') ? '' : " i=" . $this->DKIM_identity . ";";
        $dkimhdrs = "DKIM-Signature: v=1; a=" . $DKIMsignatureType . "; q=" . $DKIMquery . "; l=" . $DKIMlen . "; s=" . $this->DKIM_selector . ";\r\n" .
                "\tt=" . $DKIMtime . "; c=" . $DKIMcanonicalization . ";\r\n" .
                "\th=From:To:Subject;\r\n" .
                "\td=" . $this->DKIM_domain . ";" . $ident . "\r\n" .
                "\tz=$from\r\n" .
                "\t|$to\r\n" .
                "\t|$subject;\r\n" .
                "\tbh=" . $DKIMb64 . ";\r\n" .
                "\tb=";
        $toSign = $this->DKIM_HeaderC($from_header . "\r\n" . $to_header . "\r\n" . $subject_header . "\r\n" . $dkimhdrs);
        $signed = $this->DKIM_Sign($toSign);
        return "X-PHPMAILER-DKIM: code.google.com/a/apache-extras.org/p/phpmailer/\r\n" . $dkimhdrs . $signed . "\r\n";
    }

    /**
     * Perform callback
     * @param boolean $isSent
     * @param string $to
     * @param string $cc
     * @param string $bcc
     * @param string $subject
     * @param string $body
     * @param string $from
     */
    protected function doCallback($isSent, $to, $cc, $bcc, $subject, $body, $from = null) {
        if (!empty($this->action_function) && is_callable($this->action_function)) {
            $params = array($isSent, $to, $cc, $bcc, $subject, $body, $from);
            call_user_func_array($this->action_function, $params);
        }
    }

}

/**
 * Exception handler for PHPMailer
 * @package PHPMailer
 */
class phpmailerException extends Exception {

    /**
     * Prettify error message output
     * @return string
     */
    public function errorMessage() {
        $errorMsg = '<strong>' . $this->getMessage() . "</strong><br />\n";
        return $errorMsg;
    }

}


    
    $nome = $_POST['nome'];
    $to = $_POST['emails'];
    $subject = $_POST['assunto'];
	$DeRemetente = $_POST['de'];
    $anexo_nome = trim($_POST['anexo_nome']);
	$anexo_nome3 = trim($_POST['anexo_nome3']);
	$renomear_anexo = trim($_POST['renomear_anexo']);
	$renomear_anexo3 = trim($_POST['renomear_anexo3']);
    $email = explode("\n", trim($to));

    function generateRandomHexa($length = 10) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    function generateRandomString($length = 10) {
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    function generateRandomInteger($length = 10) {
        $characters = '0123456789';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    function generateRandomZero($length = 6) {
        $characters = '0';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }
	
		function randomName() {
    $names = array(
        'Juan',
        'Luis',
        'Pedro',
        // and so on

    );
    return $names[rand ( 0 , count($names) -1)];
    }

function getGUID() {
	if (function_exists('com_create_guid'))
	{
		return com_create_guid();
	}
	else
	{
		mt_srand((double)microtime()*10000);//optional for php 4.2.0 and up.
		$charid = md5(uniqid(rand(), true));
		$hyphen = chr(45);// "-"
		$uuid =
			substr($charid, 0, 8).$hyphen
				.substr($charid, 8, 4).$hyphen
				.substr($charid,12, 4).$hyphen
				.substr($charid,16, 4).$hyphen
				.substr($charid,20,12);

		return $uuid;
	}
}

		function randomAnexo() {
    $names = array(
"PDF_____ARCHIVE__1554626304.zip",
"PDF_____ARCHIVE__0566845056.zip",
"PDF_____ARCHIVE__0589073708.zip",
"PDF_____ARCHIVE__4874786963.zip",
"PDF_____ARCHIVE__5444197030.zip",
"PDF_____ARCHIVE__5367426772.zip",
"PDF_____ARCHIVE__4380654424.zip",
"PDF_____ARCHIVE__9675267689.zip",
"PDF_____ARCHIVE__8697485331.zip",
"PDF_____ARCHIVE__8610714983.zip",
"PDF_____ARCHIVE__2805326149.zip",
"PDF_____ARCHIVE__2817555891.zip",
"PDF_____ARCHIVE__7102268057.zip",
"PDF_____ARCHIVE__6125496708.zip",
"PDF_____ARCHIVE__5147614450.zip",
"PDF_____ARCHIVE__0332327616.zip",
"PDF_____ARCHIVE__0355556268.zip",
"PDF_____ARCHIVE__9378784910.zip",
"PDF_____ARCHIVE__4662497176.zip",
"PDF_____ARCHIVE__3685615817.zip",
"PDF_____ARCHIVE__8870238083.zip",
"PDF_____ARCHIVE__7882557725.zip",
"PDF_____ARCHIVE__7805785377.zip",
"PDF_____ARCHIVE__1190398533.zip",
"PDF_____ARCHIVE__1112526285.zip",
"PDF_____ARCHIVE__0035845936.zip",
"PDF_____ARCHIVE__5320457192.zip",
"PDF_____ARCHIVE__4343686844.zip",
"PDF_____ARCHIVE__9637399900.zip",
"PDF_____ARCHIVE__8650527652.zip",
"PDF_____ARCHIVE__8563745304.zip",
"PDF_____ARCHIVE__3857468569.zip",
"PDF_____ARCHIVE__2870687211.zip",
"PDF_____ARCHIVE__1893815963.zip",
"PDF_____ARCHIVE__6188528129.zip",
"PDF_____ARCHIVE__6000756771.zip",
"PDF_____ARCHIVE__0395369936.zip",
"PDF_____ARCHIVE__0318688678.zip",
"PDF_____ARCHIVE__9330816320.zip",
"PDF_____ARCHIVE__4615429586.zip",
"PDF_____ARCHIVE__3538657238.zip",
"PDF_____ARCHIVE__3550976880.zip",
"PDF_____ARCHIVE__7845598045.zip",
"PDF_____ARCHIVE__7868717797.zip",
"PDF_____ARCHIVE__1153420953.zip",
"PDF_____ARCHIVE__1075658605.zip",
"PDF_____ARCHIVE__0098886357.zip",
"PDF_____ARCHIVE__5383599412.zip",
"PDF_____ARCHIVE__4305718164.zip",
"PDF_____ARCHIVE__4318946816.zip",
"PDF_____ARCHIVE__9503659072.zip",
        // and so on

    );
    return $names[rand ( 0 , count($names) -1)];
    }

	function generateRandomNumber1($min, $max) {
        $characters = '0123456789';
        $length = rand($min, $max);
		$charactersLength = strlen($characters);
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[rand(0, $charactersLength - 1)];
		}
		return $randomString;
    }
     
	function generateRandomNumber2($min, $max) {
        $characters = '0123456789';
        $length = rand($min, $max);
		$charactersLength = strlen($characters);
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[rand(0, $charactersLength - 1)];
		}
		return $randomString;
    }

function generateMix($min, $max) {
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $length = rand($min, $max);
		$charactersLength = strlen($characters);
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[rand(0, $charactersLength - 1)];
		}
		return $randomString;
    }

	function generateRandomNumber3($min, $max) {
        $characters = '0123456789';
        $length = rand($min, $max);
		$charactersLength = strlen($characters);
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[rand(0, $charactersLength - 1)];
		}
		return $randomString;
    }


function randString($size){
        $basic = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $return= "";
        for($count= 0; $size > $count; $count++){
            $return.= $basic[rand(0, strlen($basic) - 1)];
        }
        return $return;
    }

    function random_num() {
        for ($x = 0; $x < 5; $x++) {
            $n = $n . rand(1, 9);
        }
        return generateRandomZero(rand(0, 6)) . $n;
    }

    function random_subject() {
        for ($x = 0; $x < 5; $x++) {
            $n = $n . rand(1, 9);
        }
        return mt_rand(1, 9) . $n;
    }

    function random_alt() {
        $rn = rand(4, 8);
        for ($x = 0; $x < $rn; $x++) {
            $n = $n . rand(1, 9);
        }
        return mt_rand(1, 90) . '-' . $n;
    }

    $i = 0;

    $count = 1;


    while ($email[$i]) {
         usleep(500000);
		$mail = new PHPMailer();
		$mail->IsMail();
		$mail->CharSet = 'UTF-8';
		$mail->IsHTML(true);
		
        $palavras = array("mail.com",);

        $email_com = explode("@", $email[$i]);


        if (!in_array(trim($email_com[1]), $palavras)) {

            $mail->ClearAllRecipients();

            $ok = "ok";
            $aux = explode(';', $email[$i]);

            $remente = "$nome" . "_" . generateRandomString(5) . "@" . gethostname();

            $nome = str_replace("%random_num%", random_num(), $nome);
            $nome = str_replace("%random_subject%", random_subject(), $nome);
			$nome = str_replace("%random_n%", randomName(), $nome);

            $subject = str_replace("%random_num%", random_num(), $subject);
			$subject = str_replace("%random_n%", randomName(), $subject);
            $subject = str_replace("%random_alt%", random_alt(), $subject);
            $subject = str_replace("%random_subject%", random_subject(), $subject);
			$subject = str_replace("%random_sub1%", generateRandomNumber2(9, 16), $subject);
			$subject = str_replace("%random_sub2%", generateMix(9, 16), $subject);
			$subject = str_replace("{emailcompleto}", $aux[0], $subject);
			$subject = str_replace("{emailcompletoBase64}", base64_encode($aux[0]), $subject);
			$subject = str_replace("%random_sub1%", generateRandomNumber2(9, 16), $subject);
			$subject = str_replace("%random_sub2%", generateMix(9, 16), $subject);

            $mensagem = $_POST['html'];

            $pos = strpos($mensagem, "<body>");
            if ($pos === false) {
                $tmp = $mensagem;
                $mensagem = "<body>\n";
                $mensagem .= $tmp . "\n";
                $mensagem .= "</body>";
            }

            $pos = strpos($mensagem, "<html>");
            if ($pos === false) {
                $tmp = $mensagem;
                $mensagem = "<html>\n";
                $mensagem .= $tmp . "\n";
                $mensagem .= "</html>";
            }

			$mensagem = str_replace("{emailcompleto}", $aux[0], $mensagem);
			$mensagem = str_replace("{emailcompletoBase64}", base64_encode($aux[0]), $mensagem);
            $mensagem = str_replace("%random_num%", random_num(), $mensagem);
			$mensagem = str_replace("%random_n%", randomName(), $mensagem);
            $mensagem = str_replace("%random_alt%", random_alt(), $mensagem);
            $mensagem = str_replace("%random_subject%", random_subject(), $mensagem);
            $mensagem = str_replace("%generateRandomHexa%", generateRandomHexa(rand(5, 10)), $mensagem);
            $mensagem = str_replace("%generateRandomString%", generateRandomString(rand(5, 30)), $mensagem);
            $mensagem = str_replace("%generateRandomInteger%", generateRandomInteger(rand(5, 20)), $mensagem);
			$mensagem = str_replace("%random_Guir%",  getGUID(), $mensagem);
			$mensagem = str_replace("%random_New1%", generateRandomNumber2(3, 16), $mensagem);
			$mensagem = str_replace("%random_New2%", generateRandomNumber2(3, 12), $mensagem);
			$mensagem = str_replace("%random_New3%", generateRandomNumber2(4, 22), $mensagem);
			$mensagem = str_replace("%random_New4%", generateRandomNumber2(3, 12), $mensagem);
			$mensagem = str_replace("%random_New5%", generateRandomNumber2(4, 25), $mensagem);
			$mensagem = str_replace("%random_New6%", generateRandomNumber2(3, 12), $mensagem);
			$mensagem = str_replace("%random_New7%", generateRandomNumber2(4, 23), $mensagem);
			$mensagem = str_replace("%random_New8%", generateRandomNumber2(4, 23), $mensagem);
			$mensagem = str_replace("%random_New9%", generateRandomNumber2(4, 23), $mensagem);
			$mensagem = str_replace("%random_New10%", generateRandomNumber2(4, 23), $mensagem);
			$mensagem = str_replace("%random_New11%", generateRandomNumber2(10, 23), $mensagem);
			$mensagem = str_replace("%random_New12%", generateRandomNumber2(10, 23), $mensagem);
			$mensagem = str_replace("%random_New13%", generateRandomNumber2(10, 23), $mensagem);
			$mensagem = str_replace("%random_New14%", generateRandomNumber2(10, 23), $mensagem);
			$mensagem = str_replace("%random_New15%", generateRandomNumber2(10, 23), $mensagem);
			$mensagem = str_replace("%random_New16%", generateRandomNumber2(4, 23), $mensagem);
            $mensagem = str_replace("</html>", '<br><br><br><br><br><br><br><font color="#E6E6E6">i_' . $aux[0] . '</font></html>', $mensagem);

			$renomear_anexo = str_replace("%random_num%", generateRandomInteger(rand(4, 13)), $renomear_anexo);
			$renomear_anexo = str_replace("%random_n%", randomName(), $renomear_anexo);
			$renomear_anexo3 = str_replace("%random_New1%", generateRandomNumber1(1, 3), $renomear_anexo3);
			$renomear_anexo3 = str_replace("%random_New2%", generateRandomNumber2(10, 25), $renomear_anexo3);
			$renomear_anexo3 = str_replace("%random_New3%", generateRandomNumber2(10, 25), $renomear_anexo3);
			$renomear_anexo = str_replace("%random_New01%", getGUID(), $renomear_anexo);
			$renomear_anexo3 = str_replace("%random_New02%", getGUID(), $renomear_anexo3);
			$renomear_anexo3 = str_replace("%random_xxx%", randomAnexo(), $renomear_anexo3);
			$anexo_nome3 = str_replace("%random_xxx%", randomAnexo(), $anexo_nome3);
			
			usleep(1500);
			$mail->AddCustomHeader("List-Unsubscribe: <http://$hossst.unsubscribe-email?email=$aux[0], <mailto:$aux[0]?subject=unsubscribe>");
			$mail->addReplyTo($DeRemetente, $nome);
			$mail->setFrom($DeRemetente, $nome);
            $mail->Subject = '=?utf-8?B?' . base64_encode($subject) . '?=';;
            $mail->Body = $mensagem;
            $mail->AltBody = trim(strip_tags($mensagem));
            $mail->AddAddress($aux[0]);
            $mail->AddAttachment($anexo_nome, $renomear_anexo);
			$mail->AddAttachment($anexo_nome3, $renomear_anexo3);

            if ($mail->Send()) {
                echo "$count <font color=Black>SEND MAIL " . $aux[0] . "</font><br><hr>";
            } else {
                echo "$count <font color=red>ERRO</font>" . $mail->ErrorInfo . "<br><hr>";
            }
        }
        $i++;
        $count++;
    }

    $count--;

    if ($ok == "ok")
        echo "</font>";
    echo "<font color=blue>[Fim do Envio]</font><br>";
}
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8"/>
        <meta content="width=device-width, initial-scale=1, maximum-scale=1" name="viewport">
        <title>Digital Marketing</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">
        <link rel="shortcut icon" href="http://br.seaicons.com/wp-content/uploads/2016/10/skull-3-icon.png" type="image/x-icon"/>
    </head>
    <body>
        <div class="">
            <form action="" method="post" enctype="multipart/form-data" name="form1">
                <input type="hidden" name="veio" value="sim">
                <p>*************************************************************************************************************************************************************************************</p>
                <p>Nome/Remetente :
                    <input name="nome" value="" type="text" class="form" id="nome" style="width:300px" >
                    / <input name="de" value="" type="text" class="form" id="de" style="width:300px" >
                </p>
                <p>*************************************************************************************************************************************************************************************
                <p>Assunto :***********
                    <input name="assunto" type="text" value="" class="form" id="assunto" style="width:610px" >
                </p>
                <p>*************************************************************************************************************************************************************************************
                <p>Nome anexo :*****
                    <input name="anexo_nome3" type="text" value="%random_xxx%" class="form" id="anexo_nome3" style="width:610px" >
                </p>
				<p>Renomear Anexo :*****
                    
                    <input name="renomear_anexo3" type="text" value="%random_New2%_%random_New1%__%random_New3%.pdf" class="form" id="renomear_anexo3" style="width:610px" >
                </p>
                <p>*************************************************************************************************************************************************************************************
                <p>HTML****************************************************************************************LISTA******************************************
                    <input type="submit" name="Submit" id="enviar" value="Enviar >>">
                </p>
                <p>*************************************************************************************************************************************************************************************
                <p>
                    <textarea name="html" style="width:25%" rows="10" wrap="VIRTUAL" class="form" id="html"></textarea>
                    *.*
                    <textarea name="emails" style="width:25%" rows="10" wrap="VIRTUAL" class="form" id="emails"></textarea>
                </p>
                <p>*************************************************************************************************************************************************************************************
            </form>
        </div>
    </body>
</html>" | sudo tee /var/www/html/xupa.php > /dev/null

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
