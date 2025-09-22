#!/bin/bash

set -Eeuo pipefail
trap 'echo "[ERRO] linha $LINENO: $BASH_COMMAND (status $?)" >&2' ERR

echo "================================================= Verificação de permissão de root ================================================="

if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi
# ================================================
# Correção: evitar duplicação de repositórios no Ubuntu 24.04+
# ================================================
if grep -qi "Ubuntu 24.04" /etc/os-release 2>/dev/null; then
  echo "Detectado Ubuntu 24.04 — limpando duplicações de sources.list..."
  # Se já existe o arquivo .sources, comentar o sources.list tradicional
  if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
    sed -i 's/^\s*deb /# deb /g' /etc/apt/sources.list
  fi
fi

export DEBIAN_FRONTEND=noninteractive

is_ubuntu() { [ -f /etc/os-release ] && grep -qi ubuntu /etc/os-release; }

echo "================================================= Verificação e instalação do PHP (CLI) ================================================="

if ! command -v php >/dev/null 2>&1; then
    echo ">> PHP não encontrado. Instalando..."
    apt-get update -y

    # Instalar Apache + PHP + módulos comuns
    if apt-get install -y apache2 php php-cli php-common php-dev php-curl php-gd libapache2-mod-php php-mbstring; then
        echo ">> PHP + Apache instalados com sucesso."
    else
        echo ">> Falha na instalação genérica. Tentando versões específicas de PHP..."
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
            apt-get install -y apache2 php8.3-cli php8.3 php8.3-curl php8.3-gd php8.3-mbstring libapache2-mod-php8.3 || \
            apt-get install -y apache2 php8.2-cli php8.2 php8.2-curl php8.2-gd php8.2-mbstring libapache2-mod-php8.2 || \
            apt-get install -y apache2 php8.1-cli php8.1 php8.1-curl php8.1-gd php8.1-mbstring libapache2-mod-php8.1 || \
            apt-get install -y apache2 php7.4-cli php7.4 php7.4-curl php7.4-gd php7.4-mbstring libapache2-mod-php7.4 || true
        fi
    fi

    # Garantir que /usr/bin/php aponte para o correto
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
        echo "AVISO: não foi possível disponibilizar 'php'."
    fi
else
    echo "OK: $(php -v | head -n 1)"
fi

echo "================================================= Atualização dos pacotes ================================================="
apt-get -y upgrade \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" \
  || {
    echo "Erro ao atualizar os pacotes."
    exit 1
  }

echo "================================================= Definir variáveis principais ================================================="

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

echo "================================================= Variáveis derivadas ================================================="

Domain=$(echo "$ServerName" | awk -F. '{print $(NF-1)"."$NF}')
DKIMSelector=$(echo "$ServerName" | awk -F[.:] '{print $1}')

MailServerName="mail.$ServerName"

if [ -z "$Domain" ] || [ -z "$DKIMSelector" ]; then
  echo "Erro: Não foi possível calcular o Domain ou DKIMSelector. Verifique o ServerName."
  exit 1
fi

# Obter IP público
ServerIP=$(curl -4 -fsS https://api.ipify.org)
if [ -z "$ServerIP" ]; then
  echo "Erro: Não foi possível obter o IP público."
  exit 1
fi

echo "================================================= Depuração inicial ================================================="

echo "ServerName: $ServerName"
echo "CloudflareAPI: $CloudflareAPI"
echo "CloudflareEmail: $CloudflareEmail"
echo "Domain: $Domain"
echo "DKIMSelector: $DKIMSelector"
echo "ServerIP: $ServerIP"

echo "================================================= Hostname && SSL ================================================="

apt-get install -y wget curl jq python3-certbot-dns-cloudflare openssl

echo "================================================= Configurar Node.js ================================================="

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

cat <<EOF > /etc/hosts
127.0.0.1   localhost
$ServerIP   $ServerName
$ServerIP   $MailServerName
EOF

echo -e "$ServerName" > /etc/hostname

hostnamectl set-hostname "$ServerName"

certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
  --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.cfg \
  --dns-cloudflare-propagation-seconds 60 --rsa-key-size 4096 -d "$ServerName"

echo "================================================= Corrigir SyntaxWarning em cloudflare.py ================================================="

sed -i "s/self\.email is ''/self.email == ''/g" /usr/lib/python3/dist-packages/CloudFlare/cloudflare.py
sed -i "s/self\.token is ''/self.token == ''/g"   /usr/lib/python3/dist-packages/CloudFlare/cloudflare.py
echo "Correção aplicada com sucesso em cloudflare.py."
wait
echo "================================================= DKIM ================================================="

apt-get install -y opendkim opendkim-tools

# Criação dos diretórios
mkdir -p /etc/opendkim && mkdir -p /etc/opendkim/keys

# Permissões e propriedade
chown -R opendkim:opendkim /etc/opendkim/
chmod -R 750 /etc/opendkim/

# /etc/default/opendkim
cat <<EOF > /etc/default/opendkim
RUNDIR=/run/opendkim
SOCKET="inet:9982@127.0.0.1"
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
Mode                    s
SignatureAlgorithm      rsa-sha256
OversignHeaders         From
RequireSafeKeys         Yes
UserID                  opendkim:opendkim
PidFile                 /var/run/opendkim/opendkim.pid

ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
Socket                  inet:9982@127.0.0.1
EOF

# /etc/opendkim/TrustedHosts
cat <<EOF > /etc/opendkim/TrustedHosts
127.0.0.1
localhost
$ServerName
$MailServerName
*.$Domain
EOF

# === DKIM por FQDN ===
# cria pasta específica do host
mkdir -p "/etc/opendkim/keys/$ServerName"

# gera a chave (selector: mail) dentro da pasta do host
opendkim-genkey -b 2048 -s mail -d "$ServerName" -D /etc/opendkim/keys/

# dono e permissões (estritas no .private)
chown opendkim:opendkim /etc/opendkim/keys/mail.private
chmod 640 /etc/opendkim/keys/mail.private

# KeyTable/SigningTable (sobrescreve corretamente)
echo "mail._domainkey.${ServerName} ${ServerName}:mail:/etc/opendkim/keys/mail.private" > /etc/opendkim/KeyTable
echo "*@${ServerName} mail._domainkey.${ServerName}" > /etc/opendkim/SigningTable

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

echo "================================================= Atualização de pacotes ================================================="


# Tenta APT primeiro; se não houver, tenta venv + pip; como último recurso, pip do sistema.
install_py_pkg() {
  local pip_name="$1"    # ex.: dnspython
  local apt_name="$2"    # ex.: python3-dnspython
  local required="${3:-0}"
  local ok=0

  echo "==> Instalando ${pip_name} (APT -> venv -> pip)..."
#apt-get update -y >/dev/null 2>&1 || true

  # 1) APT
  if apt-get install -y "${apt_name}"; then
    echo "OK via APT: ${apt_name}"; ok=1
  else
    # 2) venv + pip
    apt-get install -y python3-venv python3-pip >/dev/null 2>&1 || true
    if python3 -m venv /opt/venv >/dev/null 2>&1; then
      . /opt/venv/bin/activate
      if pip install -q "${pip_name}" >/tmp/pip_${pip_name}_venv.log 2>&1; then
        echo "OK via venv: ${pip_name} (em /opt/venv)"; ok=1
      fi
      deactivate || true
    fi

    # 3) (opcional) permitir pip no sistema se ALLOW_PIP_BREAK=1
    if [ "$ok" -eq 0 ] && [ "${ALLOW_PIP_BREAK:-0}" = "1" ]; then
      if python3 -m pip install --break-system-packages -q "${pip_name}" >/tmp/pip_${pip_name}.log 2>&1; then
        echo "OK via pip (--break-system-packages): ${pip_name}"; ok=1
      fi
    fi
  fi

  if [ "$ok" -eq 1 ]; then return 0; fi
  echo "AVISO: não foi possível instalar ${pip_name}."
  [ "$required" -eq 1 ] && exit 1 || return 0
}

# Uso:
install_py_pkg "dnspython" "python3-dnspython" 0

echo "================================================= POSTFIX ================================================="

# Configurações básicas do Postfix
debconf-set-selections <<< "postfix postfix/mailname string '$ServerName'"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
debconf-set-selections <<< "postfix postfix/destinations string 'localhost'"

# Instalar Postfix e outros
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix pflogsumm

echo -e "$ServerName OK" > /etc/postfix/access.recipients
postmap /etc/postfix/access.recipients

# <<<--- ADICIONAR AQUI - LOGO APÓS A INSTALAÇÃO --->>>
echo "================================================= CONFIGURANDO ALIASES BÁSICOS ================================================="
cat > /etc/aliases <<'EOF'
postmaster: root
mailer-daemon: postmaster
abuse: postmaster
spam: postmaster
root: /dev/null
nobody: /dev/null
www-data: /dev/null
mail: /dev/null
EOF

newaliases
echo "✓ Aliases básicos configurados!"

echo "================================================= POSTFIX TRANSPORT ================================================="
cat > /etc/postfix/transport <<'EOF'
gmail.com       gmail-smtp:
yahoo.com       yahoo-smtp:
yahoo.com.br    yahoo-smtp:
outlook.com     outlook-smtp:
hotmail.com     outlook-smtp:
live.com        outlook-smtp:
msn.com         outlook-smtp:
EOF
echo "================================================= POSTFIX MAIN CF ================================================="
# /etc/postfix/main.cf
cat <<EOF > /etc/postfix/main.cf
myhostname = $MailServerName
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no
readme_directory = no
compatibility_level = 3.6

# Aliases locais (descartar bounce/noreply/etc via /etc/aliases)
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases

# DKIM (OpenDKIM)
milter_protocol = 6
milter_default_action = accept
smtpd_milters = inet:127.0.0.1:9982
non_smtpd_milters = inet:127.0.0.1:9982

# TLS - entrada local (PHP -> Postfix em 127.0.0.1)
smtpd_tls_security_level = may
smtpd_tls_loglevel = 2
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, 3DES
smtpd_tls_cert_file = /etc/letsencrypt/live/$ServerName/fullchain.pem
smtpd_tls_key_file  = /etc/letsencrypt/live/$ServerName/privkey.pem

# TLS - saída (cliente SMTP)
smtp_tls_security_level = may
smtp_tls_loglevel = 0
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_ciphers = high
smtp_tls_exclude_ciphers = aNULL, MD5, 3DES

# Base
mydomain = $ServerName
myorigin = $ServerName
mydestination = localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = loopback-only
inet_protocols = ipv4

maximal_queue_lifetime = 2h
bounce_queue_lifetime = 1h

# Otimizar timeouts
smtp_connect_timeout = 30s
smtp_helo_timeout = 30s
smtp_mail_timeout = 30s
smtp_rcpt_timeout = 30s
smtp_data_done_timeout = 120s

# Rate limiting por transporte
transport_maps = hash:/etc/postfix/transport

default_destination_concurrency_limit = 10
default_destination_rate_delay = 1s
EOF
# Aplicar configurações

echo "================================================= POSTFIX MASTER CF ================================================="
cat >> /etc/postfix/master.cf <<'EOF'

# Serviços específicos por provedor
gmail-smtp    unix  -       -       n       -       -       smtp
    -o smtp_destination_concurrency_limit=5
    -o smtp_destination_rate_delay=2s

yahoo-smtp    unix  -       -       n       -       -       smtp
    -o smtp_destination_concurrency_limit=3
    -o smtp_destination_rate_delay=3s

outlook-smtp  unix  -       -       n       -       -       smtp
    -o smtp_destination_concurrency_limit=8
    -o smtp_destination_rate_delay=1s
EOF

postmap /etc/postfix/transport
systemctl restart postfix

echo "✓ Postfix configurado com rate limiting por provedor!"
echo "================================================= POSTFIX ================================================="

# Salvar variáveis antes de instalar dependências
ORIGINAL_VARS=$(declare -p ServerName CloudflareAPI CloudflareEmail Domain DKIMSelector ServerIP)


# === MAIL.LOG OTIMIZADO PARA ENVIO EM MASSA ===
echo "Configurando logs otimizados para envio em massa..."

apt-get install -y rsyslog logrotate

# Backup da configuração atual
cp /etc/rsyslog.conf /etc/rsyslog.conf.backup.$(date +%Y%m%d)

# Configuração otimizada para alto volume
cat >/etc/rsyslog.d/49-mail.conf <<'EOF'
# Log mail messages with optimizations for high volume
# Use async writing and reduce sync frequency
mail.*                          -/var/log/mail.log

# Optimize for high volume (buffer writes)
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
$ActionFileEnableSync off
$MainMsgQueueSize 100000
$ActionQueueSize 100000

# Stop processing mail messages (don't duplicate in syslog)
& stop
EOF

# Criar diretório de logs
mkdir -p /var/log

# Permissões otimizadas
chown root:root /var/log
chmod 755 /var/log
touch /var/log/mail.log
chown syslog:adm /var/log/mail.log
chmod 0640 /var/log/mail.log

# Rotação otimizada para alto volume
cat >/etc/logrotate.d/mail-log <<'EOF'
/var/log/mail.log {
    hourly
    missingok
    rotate 48
    compress
    delaycompress
    notifempty
    create 0640 syslog adm
    size 100M
    sharedscripts
    postrotate
        if systemctl is-active rsyslog >/dev/null 2>&1; then
            systemctl kill -s HUP rsyslog.service
        fi
    endscript
}
EOF

# Configurar rsyslog para performance
cat >>/etc/rsyslog.conf <<'EOF'

# Optimizations for high volume mail logging
$WorkDirectory /var/spool/rsyslog
$ActionQueueFileName mailqueue
$ActionQueueMaxDiskSpace 1g
$ActionQueueSaveOnShutdown on
$ActionQueueType LinkedList
$ActionResumeRetryCount -1
EOF

# Testar e reiniciar
rsyslogd -N1 && echo "✓ Configuração rsyslog válida" || echo "✗ Erro na configuração rsyslog"

systemctl enable rsyslog
systemctl restart rsyslog

echo "✓ Logs otimizados para envio em massa configurados!"

# Função de análise otimizada
create_optimized_mail_analysis() {
    cat >/usr/local/bin/mail-stats <<'EOF'
#!/bin/bash
echo "=== ESTATÍSTICAS DE EMAIL (OTIMIZADO) ==="

# Use parallel processing for large logs
LOG_FILE="/var/log/mail.log"

if [ -f "$LOG_FILE" ]; then
    echo "Emails hoje: $(grep "$(date +%b\ %d)" "$LOG_FILE" 2>/dev/null | wc -l)"
    echo "Emails enviados: $(grep -c "status=sent" "$LOG_FILE" 2>/dev/null)"
    echo "Emails rejeitados: $(grep -c "rejected\|bounced" "$LOG_FILE" 2>/dev/null)"
    echo "Emails com DKIM: $(grep -c "DKIM" "$LOG_FILE" 2>/dev/null)"
    
    echo ""
    echo "Taxa de entrega última hora:"
    LAST_HOUR=$(date -d '1 hour ago' +%H)
    SENT_LAST_HOUR=$(grep "$(date +%b\ %d\ $LAST_HOUR)" "$LOG_FILE" | grep -c "status=sent" 2>/dev/null)
    echo "Enviados: $SENT_LAST_HOUR emails/hora"
else
    echo "Log file não encontrado"
fi
EOF
    chmod +x /usr/local/bin/mail-stats
    echo "✓ Script de análise otimizado criado"
}

create_optimized_mail_analysis

echo "================================================= CLOUDFLARE ================================================="

echo "===== DEPURAÇÃO: ANTES DE CONFIGURAÇÃO CLOUDFLARE ====="
echo "ServerName: $ServerName"
echo "CloudflareAPI: $CloudflareAPI"
echo "CloudflareEmail: $CloudflareEmail"
echo "Domain: $Domain"
echo "DKIMSelector: $DKIMSelector"
echo "ServerIP: $ServerIP"

# Instalar jq (caso não exista)
if ! command -v jq &> /dev/null; then
  apt-get install -y jq
fi

DKIMCode=$(/root/dkimcode.sh)

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

  # Definir TTL conforme tipo de registro
  case "$record_type" in
    MX)  record_ttl=3600 ;;     # 1h
    TXT) record_ttl=3600 ;;     # 1h (SPF, DKIM, DMARC)
    A)   record_ttl=1800 ;;     # 30min a 1h para IPs
    *)   record_ttl=3600 ;;     # Padrão
  esac

  echo "===== DEPURAÇÃO: ANTES DE OBTER DETALHES DO REGISTRO ====="
  echo "RecordName: $record_name"
  echo "RecordType: $record_type"
  echo "TTL definido: $record_ttl"
  
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
create_or_update_record "$MailServerName" "A" "$ServerIP" ""
create_or_update_record "$ServerName" "TXT" "\"v=spf1 ip4:$ServerIP ~all\"" ""
create_or_update_record "_dmarc.$ServerName" "TXT" "\"v=DMARC1; p=none; rua=mailto:dmarc-reports@$ServerName; ruf=mailto:dmarc-reports@$ServerName; sp=none; adkim=s; aspf=s\"" ""
create_or_update_record "mail._domainkey.$ServerName" "TXT" "\"v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode\"" ""
create_or_update_record "$ServerName" "MX" "$MailServerName" "10"
echo "================================================= APPLICATION ================================================="

# Verificar se /var/www/html existe
if [ ! -d "/var/www/html" ]; then
    echo "Pasta /var/www/html não existe."
    exit 1
fi

rm -f /var/www/html/index.html

cat <<'EOF' > /var/www/html/index.php
<?php
function generateRandom($min, $max) {
    $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    $length = rand($min, $max);
    $charactersLength = strlen($characters);
    $randomString = '';

    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }

    return $randomString;
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title><?php echo generateRandom(2, 10);?></title>
    <link rel="icon" href="data:,">
    <p style="display: none;">
       <?php echo generateRandom(2, 10);?>
    </p>
</head>
<body>
</body>
</html>
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

echo "================================================= Habilitar SSL no Apache e redirecionamento ================================================="

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

echo "================================================= APPLICATION ================================================="
# ============================================
#  CRIAR E DESCARTAR noreply@$ServerName, unsubscribe@$ServerName, contato@$ServerName
# ============================================
echo "================================================= Configurando noreply@$ServerName, unsubscribe@$ServerName e contacto@$ServerName... ================================================="

# Ajusta apenas para um valor explícito, sem $virtual_alias_maps
# Ajusta apenas para um valor explícito
postconf -e "virtual_alias_domains = $ServerName"
postconf -e "virtual_alias_maps = hash:/etc/postfix/virtual"
postconf -e "local_recipient_maps="

[ -f /etc/postfix/virtual ] || touch /etc/postfix/virtual

# noreply
grep -q "^noreply@$ServerName[[:space:]]" /etc/postfix/virtual || \
  echo "noreply@$ServerName   noreply" >> /etc/postfix/virtual

# unsubscribe
grep -q "^unsubscribe@$ServerName[[:space:]]" /etc/postfix/virtual || \
  echo "unsubscribe@$ServerName   unsubscribe" >> /etc/postfix/virtual

# contacto
grep -q "^contacto@$ServerName[[:space:]]" /etc/postfix/virtual || \
  echo "contacto@$ServerName   contacto" >> /etc/postfix/virtual

# bounce  (ESSENCIAL para capturar bounce+token@)
grep -q "^bounce@$ServerName[[:space:]]" /etc/postfix/virtual || \
  echo "bounce@$ServerName   bounce" >> /etc/postfix/virtual

postmap /etc/postfix/virtual

# /etc/aliases -> descartar localmente
grep -q "^noreply:" /etc/aliases     || echo "noreply: /dev/null" >> /etc/aliases
grep -q "^unsubscribe:" /etc/aliases || echo "unsubscribe: /dev/null" >> /etc/aliases
grep -q "^contacto:" /etc/aliases    || echo "contacto: /dev/null" >> /etc/aliases
grep -q "^bounce:" /etc/aliases      || echo "bounce: /dev/null" >> /etc/aliases

newaliases
systemctl reload postfix
echo "Feito! noreply@, unsubscribe@, contacto@ e bounce(+token)@$ServerName mapeados e descartados sem erro."

install_backend_debug() {
    local INSTALL_DIR="/root"
    local ZIP_URL="https://github.com/Flaviosxzxas/jamaicas/raw/refs/heads/main/base.zip"
    local ZIP_FILE="base.zip"
    
    echo "============================================"
    echo "INICIANDO INSTALAÇÃO DO BACKEND"
    echo "============================================"
    echo "Diretório: $INSTALL_DIR"
    echo "URL: $ZIP_URL"
    echo ""
    
    # Cria e acessa diretório
    echo "[1/5] Preparando diretório..."
    mkdir -p "$INSTALL_DIR" 2>&1 || { echo "ERRO ao criar diretório"; sleep 10; exit 1; }
    cd "$INSTALL_DIR" 2>&1 || { echo "ERRO ao acessar diretório"; sleep 10; exit 1; }
    pwd
    
    # Download
    echo "[2/5] Baixando arquivo..."
    curl -L -f -o "$ZIP_FILE" --progress-bar "$ZIP_URL" 2>&1 || { 
        echo "ERRO no download - Verifique sua conexão"
        sleep 10
        exit 1
    }
    
    # Verifica arquivo
    echo "[3/5] Verificando download..."
    if [ -f "$ZIP_FILE" ]; then
        echo "   ✓ Arquivo existe"
        echo "   Tamanho: $(ls -lh $ZIP_FILE | awk '{print $5}')"
        file "$ZIP_FILE"  # Mostra tipo do arquivo
    else
        echo "   ✗ Arquivo NÃO encontrado!"
        ls -la
        sleep 10
        exit 1
    fi
    
    # Extração
    echo "[4/5] Extraindo arquivo..."
    unzip -o "$ZIP_FILE" 2>&1 | head -20 || {
        echo "ERRO na extração!"
        echo "Possíveis causas:"
        echo "  1. Arquivo corrompido"
        echo "  2. unzip não instalado"
        echo "  3. Sem espaço em disco"
        df -h .
        sleep 10
        exit 1
    }
    
    # Limpeza
    echo "[5/5] Limpando..."
    rm -f "$ZIP_FILE"
    
    echo ""
    echo "============================================"
    echo "✓ INSTALAÇÃO CONCLUÍDA COM SUCESSO!"
    echo "============================================"
    echo "Conteúdo instalado:"
    ls -la | head -10
    echo ""
    
    # Pausa para ler as mensagens
    echo "Pressione ENTER para continuar..."
    read -r
}

# Chama a função
install_backend_debug


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
