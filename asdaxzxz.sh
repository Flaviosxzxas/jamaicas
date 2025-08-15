# ============================================
#  Verificação de permissão de root
# ============================================
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

is_ubuntu() { [ -f /etc/os-release ] && grep -qi ubuntu /etc/os-release; }

# ============================================
#  Verificação e instalação do PHP (CLI)
# ============================================
echo ">> Verificando se o PHP está instalado..."
if ! command -v php >/dev/null 2>&1; then
    echo ">> PHP não encontrado. Instalando..."
    apt-get update -y

    # Caminho rápido: meta-pacote genérico
    if apt-get install -y php-cli php-common; then
        :
    else
        echo ">> 'php-cli' indisponível. Tentando versões específicas..."
        # tenta detectar versões disponíveis no repo e instalar a mais alta
        CANDIDATES="$(apt-cache search -n '^php[0-9]\.[0-9]-cli$' | awk '{print $1}' | sort -Vr)"
        OK=0
        for pkg in $CANDIDATES php8.3-cli php8.2-cli php8.1-cli php7.4-cli; do
            if apt-get install -y "$pkg"; then OK=1; break; fi
        done
        if [ "$OK" -eq 0 ] && is_ubuntu; then
            echo ">> Adicionando PPA ppa:ondrej/php (fallback)..."
            apt-get install -y software-properties-common ca-certificates lsb-release || true
            add-apt-repository -y ppa:ondrej/php || true
            apt-get update -y
            apt-get install -y php8.3-cli || apt-get install -y php8.2-cli || apt-get install -y php8.1-cli || apt-get install -y php7.4-cli || true
        fi
    fi

    # Garante que /usr/bin/php aponte para o binário instalado via update-alternatives
    PHPPATH="$(command -v php || true)"
    if [ -n "$PHPPATH" ] && [ "$PHPPATH" != "/usr/bin/php" ]; then
        echo ">> Registrando ${PHPPATH} como alternativa de php..."
        update-alternatives --install /usr/bin/php php "$PHPPATH" 80 || true
        update-alternatives --set php "$PHPPATH" || true
        hash -r || true
    fi

    if command -v php >/dev/null 2>&1; then
        echo "OK: $(php -v | head -n 1)"
    else
        echo "AVISO: não foi possível disponibilizar 'php'. O script seguirá mesmo assim."
    fi
else
    echo "OK: $(php -v | head -n 1)"
fi

# ============================================
#  Atualização dos pacotes do sistema
# ============================================
echo ">> Atualizando pacotes..."
apt-get update
apt-get -y upgrade \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" \
  || {
    echo "Erro ao atualizar os pacotes."
    exit 1
  }

# (Opcional) Após o upgrade, recalcule a versão do PHP do CLI se for usar em passos seguintes:
# PHPV="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
# echo "PHP CLI ativo: $PHPV"


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
ServerIP=$(curl -fsS https://api64.ipify.org)
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
curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
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
# mantenha apenas:
sed -i "s/self\.email is ''/self.email == ''/g" /usr/lib/python3/dist-packages/CloudFlare/cloudflare.py
sed -i "s/self\.token is ''/self.token == ''/g"   /usr/lib/python3/dist-packages/CloudFlare/cloudflare.py
# REMOVA esta linha:
# sed -i "s/self.certtoken is None/self.certtoken == None/g" ...

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
# /etc/opendkim.conf
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   007
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes

Canonicalization        relaxed/relaxed
Mode                    sv
UserID                  opendkim:opendkim
PidFile                 /run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256

# Escopos e tabelas
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable

# Socket que casa com o Postfix
Socket                  inet:12301@127.0.0.1

# Segurança das chaves (pode deixar false se as permissões ainda não estiverem fechadas)
RequireSafeKeys         false

# (opcional) Se algum dia quiser testar oversign:
# OversignHeaders       From, Date, Message-ID
EOF

# /etc/opendkim/TrustedHosts
cat <<EOF > /etc/opendkim/TrustedHosts
127.0.0.1
localhost
$ServerName
::1
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
    echo '/^[Rr]eceived: by .+ \(Postfix, from userid [0-9]+\)/ IGNORE' > /etc/postfix/header_checks

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
smtpd_milters = inet:127.0.0.1:12301, inet:127.0.0.1:54321
non_smtpd_milters = \$smtpd_milters

# Restrições de destinatários
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    check_recipient_access hash:/etc/postfix/access.recipients,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain,
    reject_unauth_destination,
    reject_unlisted_recipient,
    check_policy_service inet:127.0.0.1:10045
    
# Não deixe vazio (evita aceitar locais inexistentes)
local_recipient_maps = proxy:unix:passwd.byname \$alias_maps

smtpd_client_connection_rate_limit = 100
smtpd_client_connection_count_limit = 50
anvil_rate_time_unit = 60s

message_size_limit = 10485760
default_destination_concurrency_limit = 50
maximal_queue_lifetime = 3d
bounce_queue_lifetime = 3d
smtp_destination_rate_delay = 1s

smtpd_helo_required = yes
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

smtpd_sasl_auth_enable = no
#smtpd_sasl_type = dovecot
#smtpd_sasl_path = private/auth
#smtpd_sasl_security_options = noanonymous, noplaintext
#smtpd_sasl_tls_security_options = noanonymous
#smtpd_tls_auth_only = yes

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

# === MAIL.LOG via rsyslog (com criação e rotação) ===
apt-get update -y
apt-get install -y rsyslog logrotate

# rsyslog: direcione apenas mensagens da facility "mail" para /var/log/mail.log
cat >/etc/rsyslog.d/49-mail.conf <<'EOF'
mail.*   -/var/log/mail.log
& stop
EOF

# garanta o arquivo e as permissões (Ubuntu: syslog:adm)
touch /var/log/mail.log
chown syslog:adm /var/log/mail.log
chmod 0640 /var/log/mail.log

# logrotate para /var/log/mail.log
cat >/etc/logrotate.d/mail-log <<'EOF'
/var/log/mail.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        invoke-rc.d rsyslog rotate >/dev/null 2>&1 || true
    endscript
}
EOF

# (re)ativar e reiniciar rsyslog
systemctl enable --now rsyslog
systemctl restart rsyslog

# teste rápido
logger -p mail.info "rsyslog: teste de escrita $(date)"
tail -n 5 /var/log/mail.log || true


###############################################################################
# POSTFWD (policy de rate limit por MX) rodando como postfix:postfix
###############################################################################
export DEBIAN_FRONTEND=noninteractive

echo "=== [postfwd] instalando/validando dependências…"
apt-get update -y
apt-get install -y postfwd grep sed iproute2 iputils-ping ca-certificates curl >/dev/null 2>&1 || true

# Descobre binário disponível
PFWBIN="$(command -v postfwd3 || command -v postfwd2 || command -v postfwd || true)"
if [ -z "$PFWBIN" ]; then
  echo "[postfwd] ERRO: não encontrei o binário postfwd/postfwd2 após tentar instalar."
  # não aborta o script inteiro
else
  echo "[postfwd] usando binário: $PFWBIN"
fi

# Regras (idempotente)
mkdir -p /etc/postfwd
cat >/etc/postfwd/postfwd.cf <<'EOF'
# ===== Regras postfwd2 (uma por linha; tokens separados por ";") =====
# Grandes provedores globais
id=limit-gmail;      recipient=~/.+@gmail\.com$/;                                      action=rate(global/2000/3600) defer_if_permit "Limite 2000/h atingido p/ Gmail."
id=limit-msn;        recipient=~/.+@(outlook\.com|hotmail\.com|live\.com|msn\.com)$/;  action=rate(global/1000/86400) defer_if_permit "Limite 1000/dia atingido p/ Microsoft."
id=limit-yahoo;      recipient=~/.+@yahoo\.(com|com\.br|com\.ar|com\.mx)$/;            action=rate(global/150/3600)  defer_if_permit "Limite 150/h atingido p/ Yahoo."
# Observação: domínios Google Workspace próprios não entram aqui (não são gmail.com)

# Provedores/hostings “de marca”
id=limit-kinghost;   recipient=~/.+@kinghost\.net$/;                                   action=rate(global/300/3600)  defer_if_permit "Limite 300/h atingido p/ KingHost."
id=limit-uol;        recipient=~/.+@uol\.com\.br$/;                                    action=rate(global/300/3600)  defer_if_permit "Limite 300/h atingido p/ UOL."
id=limit-locaweb;    recipient=~/.+@locaweb\.com\.br$/;                                action=rate(global/500/3600)  defer_if_permit "Limite 500/h atingido p/ Locaweb."
id=limit-mandic;     recipient=~/.+@mandic\.com\.br$/;                                 action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ Mandic."
id=limit-titan;      recipient=~/.+@titan\.email$/;                                    action=rate(global/500/3600)  defer_if_permit "Limite 500/h atingido p/ Titan."
id=limit-godaddy;    recipient=~/.+@secureserver\.net$/;                               action=rate(global/300/3600)  defer_if_permit "Limite 300/h atingido p/ GoDaddy (secureserver)."
id=limit-zimbra;     recipient=~/.+@zimbra\..+$/;                                      action=rate(global/400/3600)  defer_if_permit "Limite 400/h atingido p/ Zimbra."

# Microsoft 365 “de marca” (endereços @outlook.com já cobertos acima)
id=limit-office365;  recipient=~/.+@office365\.com$/;                                  action=rate(global/2000/3600) defer_if_permit "Limite 2000/h atingido p/ Office 365."

# Argentina — ISPs/domínios comuns
id=limit-fibertel;   recipient=~/.+@fibertel\.com\.ar$/;                               action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ Fibertel."
id=limit-speedy;     recipient=~/.+@speedy\.com\.ar$/;                                 action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ Speedy."
id=limit-personal;   recipient=~/.+@personal\.com\.ar$/;                               action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ Personal (Arnet)."
id=limit-telecom;    recipient=~/.+@telecom\.com\.ar$/;                                action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ Telecom."
id=limit-claro-ar;   recipient=~/.+@claro\.com\.ar$/;                                  action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ Claro AR."

# México — ISPs/domínios comuns
id=limit-telmex;     recipient=~/.+@prodigy\.net\.mx$/;                                action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ Telmex."
id=limit-axtel;      recipient=~/.+@axtel\.net$/;                                      action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ Axtel."
id=limit-izzi;       recipient=~/.+@izzi\.net\.mx$/;                                   action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ Izzi."
id=limit-megacable;  recipient=~/.+@megacable\.com\.mx$/;                              action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ Megacable."
id=limit-totalplay;  recipient=~/.+@totalplay\.net\.mx$/;                              action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ TotalPlay."
id=limit-telcel;     recipient=~/.+@telcel\.net$/;                                     action=rate(global/200/3600)  defer_if_permit "Limite 200/h atingido p/ Telcel."

# Catch-all (tudo que não casou acima)
id=no-limit; recipient=~/.+/;                                                           action=permit
EOF
chmod 0644 /etc/postfwd/postfwd.cf
echo "[postfwd] regras gravadas."

# Desabilita o SysV do pacote (evita 'Default-Start contains no runlevels')
systemctl stop postfwd 2>/dev/null || true
systemctl disable postfwd 2>/dev/null || true

# Unidade systemd nativa rodando como postfix:postfix
cat >/etc/systemd/system/postfwd-local.service <<'EOF'
[Unit]
Description=postfwd policy daemon (local-only)
After=network-online.target postfix.service
Wants=network-online.target
#Requires=postfix.service

[Service]
Type=forking
# Cria /run/postfwd como root antes de trocar para o usuário do serviço
PermissionsStartOnly=true
ExecStartPre=/usr/bin/install -d -o postfix -g postfix -m 0755 /run/postfwd
ExecReload=/bin/kill -HUP $MAINPID

# Importante: rodar como postfix:postfix para evitar tentativa de cair para 'nobody'
User=postfix
Group=postfix

# Executa postfwd2 em modo daemon (sem --nodaemon para rate() funcionar)
ExecStart=/usr/sbin/postfwd2 -u postfix -g postfix \
  --shortlog --summary=600 \
  --cache=600 --cache-rbl-timeout=3600 \
  --cleanup-requests=1200 --cleanup-rbls=1800 --cleanup-rates=1200 \
  --file=/etc/postfwd/postfwd.cf --interface=127.0.0.1 --port=10045

Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now postfwd-local >/dev/null 2>&1 || true

# Espera um instante e verifica se está ouvindo
sleep 1
if ss -ltn 2>/dev/null | grep -q '127\.0\.0\.1:10045'; then
  echo "[postfwd] OK: ouvindo em 127.0.0.1:10045"
  PFW_OK=1
else
  echo "[postfwd] WARN: serviço não está ouvindo; mantendo Postfix sem policy."
  PFW_OK=0
fi

# Integração no Postfix (adiciona ou remove a policy conforme status)
NEEDED='check_policy_service inet:127.0.0.1:10045'
CURRENT="$(postconf -h smtpd_recipient_restrictions 2>/dev/null || echo '')"

sanitize_csv() { echo "$1" | sed -E 's/[,[:space:]]+/, /g; s/^, //; s/, $//'; }

if [ "$PFW_OK" -eq 1 ]; then
  # Adiciona se não existir
  if ! echo "$CURRENT" | grep -qF "$NEEDED"; then
    if [ -z "$CURRENT" ]; then
      # baseline conservadora + policy
      NEWVAL="permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_unauth_destination, reject_unlisted_recipient, $NEEDED"
    else
      # remove ocorrências antigas do mesmo check antes de anexar
      CLEANED="$(echo "$CURRENT" | sed -E 's/,\s*check_policy_service inet:127\.0\.0\.1:10045//g')"
      NEWVAL="$(sanitize_csv "$CLEANED"), $NEEDED"
    fi
    postconf -e "smtpd_recipient_restrictions=$NEWVAL"
    systemctl reload postfix
    echo "[postfwd] policy adicionada em smtpd_recipient_restrictions."
  else
    echo "[postfwd] policy já presente no Postfix."
  fi
else
  # Serviço não está OK: remove a policy, se existir
  if echo "$CURRENT" | grep -qF "$NEEDED"; then
    CLEANED="$(echo "$CURRENT" | sed -E 's/,\s*check_policy_service inet:127\.0\.0\.1:10045//g; s/check_policy_service inet:127\.0\.0\.1:10045,?\s*//g')"
    CLEANED="$(sanitize_csv "$CLEANED")"
    postconf -e "smtpd_recipient_restrictions=$CLEANED"
    systemctl reload postfix
    echo "[postfwd] policy removida (fallback para não impactar envios)."
  fi
fi

# Mostra status resumido
systemctl --no-pager --full status postfwd-local | sed -n '1,20p' || true
postconf -n | grep -E '^smtpd_recipient_restrictions|^smtpd_milters|^non_smtpd_milters' || true
###############################################################################
# FIM DO BLOCO POSTFWD
###############################################################################

echo "==================================================== OpenDMARC ===================================================="

# --- Diretórios OpenDMARC (idempotente)
echo "[OpenDMARC] Criando diretórios..."
install -d -o opendmarc -g opendmarc -m 0750 /run/opendmarc
install -d -o opendmarc -g opendmarc -m 0750 /etc/opendmarc
install -d -o opendmarc -g opendmarc -m 0750 /var/log/opendmarc
install -d -o opendmarc -g opendmarc -m 0750 /var/lib/opendmarc

# --- Config OpenDMARC (arquivo determinístico; reescreve em cada run)
cat >/etc/opendmarc.conf <<EOF
# OpenDMARC básico – loopback apenas
Syslog                  true
Socket                  inet:54321@127.0.0.1
PidFile                 /run/opendmarc/opendmarc.pid

# AuthservID é o identificador do servidor que assina Authentication-Results
AuthservID              ${ServerName}
TrustedAuthservIDs      ${ServerName}

IgnoreHosts             /etc/opendmarc/ignore.hosts
HistoryFile             /var/lib/opendmarc/opendmarc.dat

# Não rejeita mensagens no milter por falha de DMARC (deixa o Postfix decidir)
RejectFailures          false
EOF
chown opendmarc:opendmarc /etc/opendmarc.conf
chmod 0644 /etc/opendmarc.conf

# --- Ignore hosts
{
  echo "127.0.0.1"
  echo "::1"
} >/etc/opendmarc/ignore.hosts
chown opendmarc:opendmarc /etc/opendmarc/ignore.hosts
chmod 0644 /etc/opendmarc/ignore.hosts

# --- Arquivo de histórico
: > /var/lib/opendmarc/opendmarc.dat
chown opendmarc:opendmarc /var/lib/opendmarc/opendmarc.dat
chmod 0644 /var/lib/opendmarc/opendmarc.dat

# --- Limpa PID antigo se existir
rm -f /run/opendmarc/opendmarc.pid

# --- Reinícios
echo "[OpenDKIM] Reiniciando OpenDKIM..."
systemctl enable opendkim >/dev/null 2>&1 || true
systemctl restart opendkim || true
if systemctl is-active --quiet opendkim; then
  echo "[OpenDKIM] OK."
else
  echo "[OpenDKIM] AVISO: falha ao iniciar OpenDKIM."
fi

echo "[OpenDMARC] Reiniciando OpenDMARC..."
systemctl enable opendmarc >/dev/null 2>&1 || true
systemctl restart opendmarc || true
if systemctl is-active --quiet opendmarc; then
  echo "[OpenDMARC] OK."
else
  echo "[OpenDMARC] AVISO: falha ao iniciar OpenDMARC."
fi

# --- Postfix depende (soft) de DKIM/DMARC (sem travar se um deles cair)
mkdir -p /etc/systemd/system/postfix.service.d

# remova algum drop-in antigo que possa criar ciclo de dependência
rm -f /etc/systemd/system/postfix.service.d/override.conf

tee /etc/systemd/system/postfix.service.d/10-milters.conf >/dev/null <<'EOF'
[Unit]
# Garanta que DKIM/DMARC sobem antes do Postfix
After=opendkim.service opendmarc.service
# Escolha UMA das linhas abaixo:
# - Use Requires= se NÃO quiser enviar sem DKIM/DMARC:
Requires=opendkim.service opendmarc.service
# - OU troque por Wants= se quiser que o Postfix suba mesmo se um deles falhar:
#Wants=opendkim.service opendmarc.service
EOF

systemctl daemon-reload

# evita StartLimitHit se o postfix já falhou antes
systemctl reset-failed postfix || true

# prepara dependências sem bloquear
systemctl try-restart --no-block opendkim opendmarc postfwd-local || true

# tenta restart com timeout curto; se demorar, dispara async e segue
if ! timeout 15s systemctl restart postfix; then
  echo "[Postfix] restart demorou; disparando restart assíncrono..."
  systemctl restart postfix --no-block || true
fi

# aguarda até 15s o serviço ficar ativo
for i in $(seq 1 15); do
  if systemctl is-active --quiet postfix; then
    echo "[Postfix] ativo."
    break
  fi
  sleep 1
done

# se ainda não estiver ativo, tenta reload com timeout (não trava)
if ! systemctl is-active --quiet postfix; then
  echo "[Postfix] ainda não ativo; tentando reload rápido..."
  timeout 8s systemctl reload postfix || true
fi

echo "[health] serviços:"
systemctl is-active --quiet rsyslog       && echo "rsyslog OK"        || echo "rsyslog FAIL"
systemctl is-active --quiet opendkim      && echo "opendkim OK"       || echo "opendkim FAIL"
systemctl is-active --quiet opendmarc     && echo "opendmarc OK"      || echo "opendmarc FAIL"
systemctl is-active --quiet postfwd-local && echo "postfwd-local OK"  || echo "postfwd-local FAIL"
systemctl is-active --quiet postfix       && echo "postfix OK"        || echo "postfix FAIL"

echo "[health] sockets locais:"
ss -ltnp | grep -E '127\.0\.0\.1:(12301|54321|10045)|:25\b' || true

echo "[health] postfix conf (policy e milters):"
postconf -n | grep -E '^smtpd_recipient_restrictions|check_policy_service|^smtpd_milters|^non_smtpd_milters' || true

echo "[OK] Fim do setup."



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

create_or_update_record "$ServerName" "A" "$ServerIP" ""
create_or_update_record "$ServerName" "TXT" "\"v=spf1 ip4:$ServerIP -all\"" ""
#create_or_update_record "$ServerName" "TXT" "\"v=spf1 a:$ServerName -all\"" ""
#create_or_update_record "$ServerName" "TXT" "\"v=spf1 ip4:$ServerIP a:$ServerName -all\"" ""
#create_or_update_record "$ServerName" "TXT" "\"v=spf1 ip4:$ServerIP a:$ServerName include:spf.antispamcloud.com include:spf.sendinblue.com include:_spf.mailerlite.com include:emsd1.com include:servers.mcsv.net include:spf.fromdoppler.com -all\"" ""
#create_or_update_record "$ServerName" "TXT" "\"v=spf1 ip4:$ServerIP a:$ServerName include:spf.antispamcloud.com -all\"" ""
create_or_update_record "_dmarc.$ServerName" "TXT" "\"v=DMARC1; p=reject; rua=mailto:dmarc-reports@$ServerName; ruf=mailto:dmarc-reports@$ServerName; sp=reject; adkim=s; aspf=s\"" ""
create_or_update_record "mail._domainkey.$ServerName" "TXT" "\"v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode\"" ""
create_or_update_record "$ServerName" "MX" "$ServerName" "10"

# ==================================================== APPLICATION ====================================================
export DEBIAN_FRONTEND=noninteractive
set -euo pipefail

# ---------- Apache/PHP base + cURL (binário e extensão PHP) ----------
echo ">> Instalando base do Apache/PHP e certificados…"
apt-get update -y
apt-get install -y \
  apache2 php php-cli php-common php-dev php-gd libapache2-mod-php php-mbstring \
  curl ca-certificates

# Garante cadeia de certificados atualizada (HTTPS)
update-ca-certificates || true

# Descobre a versão do PHP usada pelo CLI (ex.: 8.3)
PHPV="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"

echo ">> Instalando php-curl para o PHP CLI ($PHPV)…"
if ! dpkg -s "php${PHPV}-curl" >/dev/null 2>&1; then
  apt-get install -y "php${PHPV}-curl" || apt-get install -y php-curl
fi

echo ">> Habilitando módulo curl no PHP CLI…"
if command -v phpenmod >/dev/null 2>&1; then
  phpenmod -v "$PHPV" -s cli curl 2>/dev/null || \
  phpenmod -v "$PHPV"      curl 2>/dev/null || \
  phpenmod                 curl             || true
fi

echo ">> Reiniciando serviços do PHP/Apache (se existirem)…"
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable apache2 >/dev/null 2>&1 || true
  systemctl restart apache2 2>/dev/null    || true
  systemctl restart "php${PHPV}-fpm" 2>/dev/null || true
fi

# Debug curto (opcional)
php -v
php -r 'echo "curl_loaded=", (extension_loaded("curl")?"yes":"no"), " curl_init=", (function_exists("curl_init")?"yes":"no"), PHP_EOL;'

echo ">> Validando cURL no PHP CLI…"
STRICT_CURL="${STRICT_CURL:-1}"
if php -r 'exit(extension_loaded("curl") && function_exists("curl_init") ? 0 : 1);'; then
  echo "OK: php-curl ativo no CLI."
else
  echo "⚠️ AVISO: php-curl NÃO está carregado no CLI."
  if [ "$STRICT_CURL" = "1" ]; then
    echo "Abortando para evitar falhas no shortener."
    exit 2
  else
    echo "Prosseguindo mesmo assim (modo tolerante)…"
  fi
fi

echo ">> Teste rápido:"
php -r 'echo "curl_init? ", (function_exists("curl_init")?"SIM":"NAO"), PHP_EOL;'


# ---------- Webroot mínimo ----------
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
# AQUI CRIAMOS O unsubscribe.php (versão PRO) + permissões
# -----------------------------------------------------------
cat <<'EOF' > /var/www/html/unsubscribe.php
<?php
// === Config (use o MESMO segredo do email.php) ===
const UNSUB_SECRET     = 'Gx9pT3aQ1mRxW7bY5kW2nH8cV4sL0';
const UNSUB_VALID_SECS = 60 * 60 * 24 * 30; // 30 dias
const LIST_DIR         = '/var/log/unsub';
const LIST_FILE        = '/var/log/unsub/unsubscribed.txt';

// === Utils ===
function b64url($bin){ return rtrim(strtr(base64_encode($bin), '+/','-_'), '='); }
function safe_email($e){ return filter_var($e, FILTER_VALIDATE_EMAIL) ? strtolower($e) : ''; }
function ok($msg='unsubscribed'){ http_response_code(200); header('Content-Type: text/plain; charset=utf-8'); echo $msg; exit; }
function bad($msg='invalid request'){ http_response_code(400); header('Content-Type: text/plain; charset=utf-8'); echo $msg; exit; }

function verify_token($email, $ts, $sig){
  if (!$email || !$ts || !$sig) return false;
  if (abs(time() - (int)$ts) > UNSUB_VALID_SECS) return false;
  $msg = $email.'|'.$ts;
  $chk = b64url(hash_hmac('sha256', $msg, UNSUB_SECRET, true));
  return hash_equals($chk, $sig);
}

function save_unsub($email, $mode='unknown'){
  if (!$email) return false;
  if (!is_dir(LIST_DIR)) @mkdir(LIST_DIR, 0755, true);
  $line = date('c')." | $mode | ".$email.PHP_EOL;
  return (bool)@file_put_contents(LIST_FILE, $line, FILE_APPEND|LOCK_EX);
}

// ============== Fluxos ==============

// 1) One-Click (POST) — Gmail/Outlook
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Geralmente vem a URL com e/ts/sig no query string
  $e  = safe_email($_GET['e'] ?? '');
  $ts = $_GET['ts'] ?? '';
  $sg = $_GET['sig'] ?? '';

  // Fallback: alguns provedores podem enviar JSON (raro)
  if (!$e && stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false) {
    $body = json_decode(file_get_contents('php://input'), true);
    $e  = safe_email($body['e'] ?? '');
    $ts = $body['ts'] ?? '';
    $sg = $body['sig'] ?? '';
  }

  if (!verify_token($e, $ts, $sg)) bad('invalid token');
  save_unsub($e, 'one-click') ? ok('unsubscribed') : bad('write failed');
}

// 2) Clique manual (GET) com token seguro
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['e'], $_GET['ts'], $_GET['sig'])) {
  $e  = safe_email($_GET['e'] ?? '');
  $ts = $_GET['ts'] ?? '';
  $sg = $_GET['sig'] ?? '';
  if (!verify_token($e, $ts, $sg)) {
    http_response_code(400);
    ?>
    <!doctype html><meta charset="utf-8"><title>Enlace inválido</title>
    <body style="font-family:system-ui,Segoe UI,Arial">
      <h1>Enlace inválido o expirado</h1>
      <p>El enlace de cancelación no es válido o ha expirado.</p>
    </body>
    <?php
    exit;
  }
  save_unsub($e, 'click');
  http_response_code(200);
  ?>
  <!doctype html><meta charset="utf-8"><title>Suscripción cancelada</title>
  <body style="font-family:system-ui,Segoe UI,Arial;text-align:center;margin-top:12vh">
    <h1>Suscripción cancelada</h1>
    <p>Hemos registrado tu solicitud: <b><?=htmlspecialchars($e, ENT_QUOTES)?></b></p>
    <p>No volverás a recibir mensajes de esta lista.</p>
  </body>
  <?php
  exit;
}

// 3) Retrocompatibilidade: GET/POST com 'email=' simples (sem token)
//    — útil para conteúdos antigos. Não recomendado para novos envios.
$email = safe_email($_REQUEST['email'] ?? '');
if ($email) {
  save_unsub($email, 'legacy') ? ok('unsubscribed') : bad('write failed');
}

// Caso não caia em nenhum fluxo
bad('method not allowed');
EOF

# Logs (fora do webroot) e permissões
install -d -m 755 /var/log/unsub
touch /var/log/unsub/unsubscribed.txt
chown -R www-data:www-data /var/log/unsub
chmod 644 /var/log/unsub/unsubscribed.txt

# Permissões do PHP
chown www-data:www-data /var/www/html/unsubscribe.php
chmod 644 /var/www/html/unsubscribe.php

# (Opcional) Reiniciar Apache
systemctl restart apache2 || true


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

# ================== APPLICATION: endereços de função (outbound-only) ==================
# Destinos padrão (pode sobrescrever antes de chamar este bloco)
POSTMASTER_DEST="${POSTMASTER_DEST:-root}"   # ou "voce@seu-mail.com"
SUPPORT_DEST="${SUPPORT_DEST:-root}"        # ou "atendimento@seu-mail.com"
DESCARTAR_NOREPLY=${DESCARTAR_NOREPLY:-true}

add_alias() {
  local a="$1" b="$2"
  grep -qiE "^\s*${a}:" /etc/aliases 2>/dev/null || echo "${a}: ${b}" >> /etc/aliases
}

echo "Configurando aliases locais (outbound-only) para $ServerName..."

# NADA de virtual_* (fora em modo só envio)
# postconf -X virtual_alias_domains || true
# postconf -X virtual_alias_maps || true

# Garante arquivo de aliases
[ -f /etc/aliases ] || : > /etc/aliases

# --- Obrigatórios: postmaster/abuse (locais)
add_alias "postmaster" "${POSTMASTER_DEST}"
add_alias "abuse"      "${POSTMASTER_DEST}"

# --- Atendimento
add_alias "support"    "${SUPPORT_DEST}"
add_alias "contacto"   "${SUPPORT_DEST}"

# --- DMARC reports (APENAS local). Para rua/ruf externos use caixa que receba!
add_alias "dmarc-reports" "${POSTMASTER_DEST}"

# --- Unsubscribe: grava remetentes em /var/log/unsub/unsubscribed.txt
UNSUB_SCRIPT="/usr/local/bin/unsub_capture.sh"
if [ ! -x "$UNSUB_SCRIPT" ]; then
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y procmail >/dev/null 2>&1 || true  # fornece /usr/bin/formail
  cat > "$UNSUB_SCRIPT" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
LOGDIR="/var/log/unsub"
LIST="$LOGDIR/unsubscribed.txt"
mkdir -p "$LOGDIR"
SENDER="$(/usr/bin/formail -xReturn-Path: 2>/dev/null | tr -d '<>\r' | tail -n1 || true)"
[ -z "${SENDER:-}" ] && SENDER="$(/usr/bin/formail -xFrom: 2>/dev/null | sed 's/.*<\([^>]*\)>.*/\1/' | tr -d '\r' || true)"
[ -z "${SENDER:-}" ] && SENDER="unknown"
printf '%s  %s\n' "$(date -u +'%F %T')" "$SENDER" >> "$LIST"
exit 0
EOS
  chmod +x "$UNSUB_SCRIPT"
fi
add_alias "unsubscribe" "|$UNSUB_SCRIPT"

# --- Noreply: descartar ou encaminhar
if [ "${DESCARTAR_NOREPLY}" = "true" ]; then
  add_alias "noreply" "/dev/null"
else
  add_alias "noreply" "root"
fi

# --- Bounce: captura local (útil só para mensagens geradas localmente)
BNC_SCRIPT="/usr/local/bin/bounce_capture.sh"
if [ ! -x "$BNC_SCRIPT" ]; then
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y procmail >/dev/null 2>&1 || true
  cat > "$BNC_SCRIPT" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
LOGDIR="/var/log/bounce"
LIST="$LOGDIR/bounces.log"
mkdir -p "$LOGDIR"
RP="$(/usr/bin/formail -xReturn-Path: 2>/dev/null | tr -d '<>\r' | tail -n1 || true)"

TAG=""
if [[ "${RP:-}" =~ ^bounce\+([A-Za-z0-9._-]+)@ ]]; then
  TAG="${BASH_REMATCH[1]}"
fi

RECIP="$((/usr/bin/formail -xOriginal-Recipient: 2>/dev/null || true) | sed 's/.*rfc822;\s*//' | tr -d '\r')"
[ -z "${RECIP:-}" ] && RECIP="$((/usr/bin/formail -xFinal-Recipient: 2>/dev/null || true) | sed 's/.*rfc822;\s*//' | tr -d '\r')"
[ -z "${RECIP:-}" ] && RECIP="$((/usr/bin/formail -xTo: 2>/dev/null || true) | sed 's/.*<\([^>]*\)>.*/\1/' | tr -d '\r')"

STATUS="$(/usr/bin/formail -xStatus: 2>/dev/null | tr -d '\r' || true)"
DSN="$(/usr/bin/formail -xDiagnostic-Code: 2>/dev/null | tr -d '\r' || true)"

printf '%s | return_path=%s | verp_tag=%s | recip=%s | status=%s | dsn=%s\n' \
  "$(date -u +'%F %T')" "${RP:-}" "${TAG:-}" "${RECIP:-}" "${STATUS:-}" "${DSN:-}" >> "$LIST"
exit 0
EOS
  chmod +x "$BNC_SCRIPT"
fi
add_alias "bounce" "|$BNC_SCRIPT"

# Aplica aliases
newaliases || true


# ================== Logrotate para bounce e unsubscribe ==================
cat >/etc/logrotate.d/bounce-unsub <<'EOF'
/var/log/bounce/bounces.log /var/log/unsub/unsubscribed.txt {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    copytruncate
}
EOF

# Garante diretórios e permissões básicas
install -d -m 755 /var/log/bounce /var/log/unsub
touch /var/log/bounce/bounces.log /var/log/unsub/unsubscribed.txt
chown -R www-data:www-data /var/log/unsub
chown root:adm /var/log/bounce/bounces.log || true
chmod 640 /var/log/bounce/bounces.log /var/log/unsub/unsubscribed.txt || true


systemctl reload postfix
echo "Feito: abuse/postmaster -> $POSTMASTER_DEST; contacto/support -> $SUPPORT_DEST; unsubscribe capturando; noreply configurado; bounce ativo."


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
