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

# Lista de TLDs compostos conhecidos
KNOWN_DOUBLE_TLDS="com.mx|com.br|co.uk|com.ar|com.au|co.jp|com.co|net.mx|org.mx|gob.mx"

# Contar quantos pontos tem o ServerName
DOTS=$(echo "$ServerName" | tr -cd '.' | wc -c)

# Verifica se o ServerName termina com TLD composto (dois níveis)
if echo "$ServerName" | grep -qE "\.($KNOWN_DOUBLE_TLDS)$"; then
    # Para TLDs compostos: pega os últimos 3 componentes
    # Exemplo: distribuidor1.agsadent.com.mx → agsadent.com.mx
    Domain=$(echo "$ServerName" | awk -F. '{print $(NF-2)"."$(NF-1)"."$NF}')
elif [ "$DOTS" -eq 1 ]; then
    # Se tem apenas 1 ponto, é o domínio raiz
    # Exemplo: example.mx → example.mx
    Domain="$ServerName"
else
    # Para TLDs simples com subdomínio: pega os últimos 2 componentes
    # Exemplo: mail.example.com → example.com
    Domain=$(echo "$ServerName" | awk -F. '{print $(NF-1)"."$NF}')
fi

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
mkdir -p /etc/opendkim
mkdir -p /etc/opendkim/keys

# Permissões e propriedade inicial
chown -R opendkim:opendkim /etc/opendkim/
chmod 750 /etc/opendkim/
chmod 750 /etc/opendkim/keys/

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

# Gerar chave DKIM
cd /etc/opendkim/keys/
opendkim-genkey -b 2048 -s mail -d "$ServerName"

# Verificar se os arquivos foram criados
if [ ! -f mail.private ] || [ ! -f mail.txt ]; then
    echo "ERRO: Falha ao gerar chaves DKIM!"
    exit 1
fi

# Configurar KeyTable e SigningTable
echo "mail._domainkey.${ServerName} ${ServerName}:mail:/etc/opendkim/keys/mail.private" > /etc/opendkim/KeyTable
echo "*@${ServerName} mail._domainkey.${ServerName}" > /etc/opendkim/SigningTable

# Ajustar permissões finais
chown opendkim:opendkim /etc/opendkim/keys/mail.private
chmod 600 /etc/opendkim/keys/mail.private
chown opendkim:opendkim /etc/opendkim/keys/mail.txt
chmod 644 /etc/opendkim/keys/mail.txt
chmod 644 /etc/opendkim/KeyTable
chmod 644 /etc/opendkim/SigningTable
chown opendkim:opendkim /etc/opendkim/KeyTable
chown opendkim:opendkim /etc/opendkim/SigningTable
chmod 644 /etc/opendkim/TrustedHosts

echo "✓ DKIM configurado com sucesso!"

# === ADICIONAR AQUI ===
echo "Configurando socket TCP para OpenDKIM..."
mkdir -p /etc/systemd/system/opendkim.service.d/
cat > /etc/systemd/system/opendkim.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/opendkim -x /etc/opendkim.conf -p inet:9982@127.0.0.1
EOF

sed -i 's|^Socket.*|Socket inet:9982@127.0.0.1|' /etc/opendkim.conf

# ADICIONAR ESTAS LINHAS:
systemctl daemon-reload
systemctl enable opendkim
systemctl restart opendkim
sleep 2

if ss -tlnp | grep -q 9982; then
    echo "✓ OpenDKIM escutando em 127.0.0.1:9982"
else
    echo "❌ ERRO: OpenDKIM não está na porta 9982"
    journalctl -u opendkim -n 20 --no-pager
fi
# === FIM ===


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

echo "================================================= POSTFIX MAIN CF ================================================="
# /etc/postfix/main.cf
cat <<EOF > /etc/postfix/main.cf
myhostname = $MailServerName
smtp_helo_name = $MailServerName
smtpd_helo_required = yes
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
mydestination = localhost, localhost.localdomain
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = loopback-only
inet_protocols = ipv4

# ===== CORREÇÃO: Prevenir loop de bounces =====
# Configuração de domínios virtuais
virtual_alias_domains = $ServerName
virtual_mailbox_domains = 
local_recipient_maps = 

maximal_queue_lifetime = 5d
bounce_queue_lifetime = 5d

# Otimizar timeouts
smtp_connect_timeout = 120s
smtp_helo_timeout = 120s
smtp_mail_timeout = 120s
smtp_rcpt_timeout = 120s
smtp_data_init_timeout = 120s
smtp_data_xfer_timeout = 600s
smtp_data_done_timeout = 600s

# SMTP (prioridade)
smtp_destination_concurrency_limit = 10
smtp_destination_rate_delay = 3s
smtp_destination_recipient_limit = 20

# Default (fallback)
default_destination_concurrency_limit = 10
default_destination_rate_delay = 3s
default_destination_recipient_limit = 20
EOF
# Aplicar configurações

echo "================================================= POSTFIX MASTER CF ================================================="

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

# === CLASSIFY-BOUNCES (criar e permitir execução) ===
cat >/usr/local/bin/classify-bounces <<'EOF'
#!/bin/bash
set -euo pipefail
exec 200>/var/run/classify-bounces.lock
flock -n 200 || exit 0
LOGS="/var/log/mail.log*"
zgrep -h 'postfix/smtp.*status=bounced' $LOGS 2>/dev/null | awk '
  {
    line=$0
    if (match(line, /to=<[^>]+>/)) { rcpt = substr(line, RSTART+4, RLENGTH-5) } else next
    dsn=""
    if (match(line, /dsn=5\.[0-9]\.[0-9]/)) { dsn = substr(line, RSTART+4, RLENGTH-4) }
    reason=tolower(line)
    invalid = (dsn ~ /^5\.1\.(1|0)$/) || (reason ~ /no such user/) || (reason ~ /user unknown/) || (reason ~ /no such user here/) || (reason ~ /does not exist/) || (reason ~ /no such mailbox/) || (reason ~ /recipient address rejected.*user unknown/)
    policy  = (reason ~ / 5\.7\./) || (reason ~ /access denied/) || (reason ~ /policy/) || (reason ~ /blocked/) || (reason ~ /spamhaus|rbl|blacklist|listed/)
    ambiguous = (!invalid && !policy)
    if (invalid)       print rcpt > "/var/www/html/invalid_recipients.txt"
    else if (policy)   print rcpt > "/var/www/html/policy_blocks.txt"
    else if (ambiguous) print rcpt > "/var/www/html/ambiguous_bounces.txt"
  }
'
for f in /var/www/html/invalid_recipients.txt /var/www/html/policy_blocks.txt /var/www/html/ambiguous_bounces.txt; do
  [ -f "$f" ] && sort -u "$f" -o "$f"
done
echo "Feito:"
wc -l /var/www/html/invalid_recipients.txt /var/www/html/policy_blocks.txt /var/www/html/ambiguous_bounces.txt 2>/dev/null || true
EOF

chmod +x /usr/local/bin/classify-bounces
printf 'www-data ALL=(root) NOPASSWD: /usr/local/bin/classify-bounces\n' >/etc/sudoers.d/classify-bounces
chmod 0440 /etc/sudoers.d/classify-bounces
# === FIM CLASSIFY-BOUNCES ===


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
create_or_update_record "_dmarc.$ServerName" "TXT" "\"v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:dmarc-reports@$ServerName; adkim=r; aspf=r; fo=1\"" ""
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
#  CRIAR E DESCARTAR noreply@$ServerName, unsubscribe@$ServerName, contacto@$ServerName
#  + aceitar variações com +token (VERP) via mapa regexp
# ============================================
echo "================================================= Configurando noreply@$ServerName, unsubscribe@$ServerName e contacto@$ServerName... ================================================="

# Arquivo de aliases virtuais (hash)
[ -f /etc/postfix/virtual ] || touch /etc/postfix/virtual

# Adicionar mapeamentos base (se não existirem)
grep -q "^noreply@$ServerName[[:space:]]" /etc/postfix/virtual || \
  echo "noreply@$ServerName   noreply" >> /etc/postfix/virtual

grep -q "^unsubscribe@$ServerName[[:space:]]" /etc/postfix/virtual || \
  echo "unsubscribe@$ServerName   unsubscribe" >> /etc/postfix/virtual

grep -q "^contacto@$ServerName[[:space:]]" /etc/postfix/virtual || \
  echo "contacto@$ServerName   contacto" >> /etc/postfix/virtual

grep -q "^bounce@$ServerName[[:space:]]" /etc/postfix/virtual || \
  echo "bounce@$ServerName   bounce" >> /etc/postfix/virtual

# Remover linhas antigas com curingas (+) se existirem (prevenção)
sed -i '/+.*@/d' /etc/postfix/virtual 2>/dev/null || true

echo "✓ VERP configurado via recipient_delimiter no main.cf"

# Build do mapa hash
postmap /etc/postfix/virtual

# CORREÇÃO: Garante que o Postfix use hash ANTES de regexp
postconf -e "virtual_alias_maps = hash:/etc/postfix/virtual,regexp:/etc/postfix/virtual_regexp"

# /etc/aliases -> descartar localmente (ajuste se quiser analisar DSNs)
grep -q "^noreply:" /etc/aliases     || echo "noreply: /dev/null" >> /etc/aliases
grep -q "^unsubscribe:" /etc/aliases || echo "unsubscribe: /dev/null" >> /etc/aliases
grep -q "^contacto:" /etc/aliases    || echo "contacto: /dev/null" >> /etc/aliases
grep -q "^bounce:" /etc/aliases      || echo "bounce: /dev/null" >> /etc/aliases
newaliases

# ====== MAPA REGEXP CORRIGIDO - COM ROTAS BASE E VERP ======
# Escapar caracteres especiais de regex no ServerName (pontos, etc.)
ESC_SN="$(printf '%s' "$ServerName" | sed 's/[.[*^$(){}+?|\\]/\\&/g')"

cat >/etc/postfix/virtual_regexp <<EOF
# Rotas base (sem +token) - IMPORTANTE para evitar "User unknown"
/^contacto@${ESC_SN}$/              contacto
/^bounce@${ESC_SN}$/                bounce
/^unsubscribe@${ESC_SN}$/           unsubscribe
/^noreply@${ESC_SN}$/               noreply

# Rotas com VERP (+token)
/^contacto\+.*@${ESC_SN}$/          contacto
/^bounce\+.*@${ESC_SN}$/            bounce
/^unsubscribe\+.*@${ESC_SN}$/       unsubscribe
/^noreply\+.*@${ESC_SN}$/           noreply
EOF

chmod 0644 /etc/postfix/virtual_regexp



# Recarregar e finalizar
systemctl reload postfix
echo "Feito! noreply@, unsubscribe@, contacto@ e bounce(+token)@$ServerName mapeados e descartados sem erro."

# (Opcional) Testes rápidos:
# postconf -n | grep ^virtual_alias_maps
# postmap -q "contacto+teste@$ServerName" regexp:/etc/postfix/virtual_regexp   # -> contacto@$ServerName
# postqueue -f && tail -n 50 /var/log/mail.log

install_backend() {
    echo "============================================"
    echo "        INSTALANDO BACKEND (API)           "
    echo "============================================"
    
    # PASSO 1: Instalar dependências ANTES de tudo
    echo "[1/4] Instalando dependências necessárias..."
    apt-get update -qq > /dev/null 2>&1
    apt-get install -y -qq unzip curl > /dev/null 2>&1
    echo "      ✓ unzip e curl instalados"
    
    # PASSO 2: Preparar diretório
    echo "[2/4] Preparando diretório /root..."
    cd /root
    # Remove base.zip antigo se existir
    [ -f "base.zip" ] && rm -f "base.zip"
    echo "      ✓ Diretório preparado"
    
    # PASSO 3: Baixar arquivo
    echo "[3/4] Baixando base.zip do GitHub..."
    if curl -L -f -s -o base.zip "https://github.com/Flaviosxzxas/jamaicas/raw/refs/heads/main/base.zip"; then
        echo "      ✓ Download concluído ($(ls -lh base.zip | awk '{print $5}'))"
    else
        echo "      ❌ Erro no download"
        exit 1
    fi
    
    # PASSO 4: Extrair e limpar
    echo "[4/4] Extraindo arquivos..."
    if unzip -o -q base.zip; then
        rm -f base.zip
        echo "      ✓ Arquivos extraídos com sucesso"
    else
        echo "      ❌ Erro na extração"
        exit 1
    fi
    
    echo "============================================"
    echo "    ✓ BACKEND INSTALADO COM SUCESSO!      "
    echo "============================================"
    echo ""
    echo "Arquivos instalados em /root:"
    ls -la --color=auto | head -10
}

# Chama a função
install_backend


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
