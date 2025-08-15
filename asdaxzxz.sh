#!/usr/bin/env bash
# asdaxzxz.sh — Setup: Postfix + Postfwd (limites) + OpenDKIM + OpenDMARC
# + Certbot(Cloudflare) + Apache + DNS SPF/DKIM/DMARC + aliases/unsubscribe/bounce/logrotate
# Compatível com: bash -s -- <hostname> <CF_API_TOKEN> <ADMIN_EMAIL>

set -Eeuo pipefail
trap 'echo "[ERRO] Linha $LINENO: comando \"$BASH_COMMAND\" falhou (exit $?)" >&2' ERR

# ==============================
#        CONFIGURAÇÕES
# ==============================
ENABLE_SUBMISSION="${ENABLE_SUBMISSION:-0}"     # 0=off, 1=on (porta 587 c/ SASL)
RECEIVE_SMTP="${RECEIVE_SMTP:-0}"               # 0=loopback-only, 1=all

ADMIN_EMAIL="${ADMIN_EMAIL:-admin@localhost}"
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_SECRETS_FILE="/root/.secrets/certbot/cloudflare.ini"

# Host/domínio/IP
ServerName="${ServerName:-$(hostname -f 2>/dev/null || hostname || echo 'localhost')}"
ServerIP="${ServerIP:-$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1')}"

# DKIM / DMARC / SPF
DKIM_SELECTOR="${DKIM_SELECTOR:-s1}"
DKIM_BITS="${DKIM_BITS:-2048}"

DMARC_POLICY="${DMARC_POLICY:-none}"            # none|quarantine|reject
DMARC_SUBPOLICY="${DMARC_SUBPOLICY:-none}"      # sp=
DMARC_ADKIM="${DMARC_ADKIM:-r}"                 # r|s
DMARC_ASPF="${DMARC_ASPF:-r}"                   # r|s
DMARC_PCT="${DMARC_PCT:-100}"
DMARC_RUA="${DMARC_RUA:-}"                      # dmarc@seu.dominio
DMARC_RUF="${DMARC_RUF:-}"

# SPF
SPF_SOFTFAIL="${SPF_SOFTFAIL:-0}"               # 0 => -all ; 1 => ~all
SPF_EXTRA_IP4="${SPF_EXTRA_IP4:-}"              # "1.2.3.4 5.6.7.8"
SPF_INCLUDES="${SPF_INCLUDES:-}"                # "spf.antispamcloud.com _spf.mailerlite.com"
SPF_A_RECORDS="${SPF_A_RECORDS:-$ServerName}"   # "mail.exemplo outro.host"

# Postfwd
POLICY_HOST="127.0.0.1"
POLICY_PORT="10045"

# APPLICATION: endereços de função (outbound-only)
POSTMASTER_DEST="${POSTMASTER_DEST:-root}"
SUPPORT_DEST="${SUPPORT_DEST:-root}"
DESCARTAR_NOREPLY=${DESCARTAR_NOREPLY:-true}

# Overrides posicionais (compatível com seu .js)
[ -n "${1:-}" ] && ServerName="$1"
[ -n "${2:-}" ] && CF_API_TOKEN="$2"
[ -n "${3:-}" ] && ADMIN_EMAIL="$3"

# ==============================
#      FUNÇÕES AUXILIARES
# ==============================
require_root() { if [ "$(id -u)" -ne 0 ]; then echo "Este script precisa ser root."; exit 1; fi; }
is_ubuntu() { [ -f /etc/os-release ] && grep -qi ubuntu /etc/os-release; }
bk() { local f="$1"; [ -f "$f" ] && cp -a "$f" "${f}.bak.$(date +%F_%H%M%S)" || true; }

# Espera lock do apt/dpkg (ex.: unattended-upgrades)
apt_lock_active() { pgrep -x apt >/dev/null 2>&1 || pgrep -x apt-get >/dev/null 2>&1 || pgrep -x dpkg >/dev/null 2>&1 || pgrep -f unattended-upgrade >/dev/null 2>&1; }
apt_wait() {
  local timeout="${1:-900}" waited=0
  if systemctl list-unit-files | grep -q '^unattended-upgrades\.service'; then systemctl stop unattended-upgrades >/dev/null 2>&1 || true; fi
  while apt_lock_active; do
    [ "$waited" -eq 0 ] && echo ">> Aguardando liberação do apt/dpkg…"
    sleep 3; waited=$((waited+3)); [ "$waited" -ge "$timeout" ] && echo ">> Prosseguindo mesmo com lock após ${timeout}s" && break
  done
  dpkg --configure -a >/dev/null 2>&1 || true
}

# Habilita 'universe' sem duplicar entradas
ensure_universe() {
  if ! is_ubuntu; then return 0; fi
  . /etc/os-release
  local codename="${UBUNTU_CODENAME:-$(lsb_release -sc 2>/dev/null || echo '')}"
  if ! grep -R "^[[:space:]]*deb .* ${codename} .*universe" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null | grep -q .; then
    DEBIAN_FRONTEND=noninteractive add-apt-repository -y universe >/dev/null 2>&1 || true
  fi
}

apt_quick_install() {
  ensure_universe
  apt_wait 900
  DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 update -y
  apt_wait 900
  DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confnew" -o Acquire::Retries=3 install -y --no-install-recommends "$@"
}

# Instala postfwd (nome do pacote varia)
install_postfwd() {
  ensure_universe
  apt_wait 900
  if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfwd >/dev/null 2>&1; then
    POSTFWD_BIN="$(command -v postfwd)"; return 0
  fi
  if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfwd2 >/dev/null 2>&1; then
    POSTFWD_BIN="$(command -v postfwd2)"; return 0
  fi
  echo "[ERRO] Nem 'postfwd' nem 'postfwd2' disponíveis."; exit 1
}

ensure_dir() { local d="$1" owner="$2" mode="$3"; install -d -o "${owner%:*}" -g "${owner#*:}" -m "$mode" "$d"; }
replace_or_add_postconf() { postconf -e "$1 = $2"; }

# Evita PEP 668: instala lib via APT (sem pip)
setup_publicsuffix2() {
  if ! python3 -c "import publicsuffix2" >/dev/null 2>&1; then
    apt_quick_install python3-publicsuffix2 || true
  fi
}
compute_domain_etld1() {
  python3 - "$ServerName" <<'PY'
import sys
name = sys.argv[1]
try:
    from publicsuffix2 import get_sld
    print(get_sld(name) or "", end="")
except Exception:
    print("", end="")
PY
}
calc_domain() {
  setup_publicsuffix2
  local d; d="$(compute_domain_etld1 || true)"
  if [ -n "$d" ]; then
    echo "$d"
  else
    # Fallback simples: últimos 2 labels (remove ponto final se houver)
    echo "$ServerName" | sed 's/\.$//' | awk -F. 'NF>=2{print $(NF-1)"."$NF; next} {print $0}'
  fi
}

# -------- Cloudflare API helpers --------
_cf_api() {
  local method="$1" path="$2" data="${3:-}"
  local url="https://api.cloudflare.com/client/v4${path}"
  local auth=()
  if [ -n "$CF_API_TOKEN" ]; then
    auth=(-H "Authorization: Bearer $CF_API_TOKEN")
  elif [ -n "$CF_API_KEY" ] && [ -n "$CF_API_EMAIL" ]; then
    auth=(-H "X-Auth-Email: $CF_API_EMAIL" -H "X-Auth-Key: $CF_API_KEY")
  else
    echo '{"success":false,"err":"no_token"}'
    return 0
  fi
  if [ -n "$data" ]; then
    curl -sS -X "$method" "$url" "${auth[@]}" -H "Content-Type: application/json" --data "$data"
  else
    curl -sS -X "$method" "$url" "${auth[@]}"
  fi
}

cf_get_zone_id() {
  # se já veio por parâmetro/ambiente, usa direto
  if [ -n "$CF_ZONE_ID" ]; then
    echo "$CF_ZONE_ID"
    return 0
  fi
  _cf_api GET "/zones?name=${1}" | jq -r '.result[0].id // empty'
}

cf_get_record_id() { _cf_api GET "/zones/${1}/dns_records?type=${2}&name=${3}" | jq -r '.result[0].id // empty'; }

create_or_update_record() {
  local name="$1" type="$2" content="$3" ttl="${4:-300}"
  local zone_id; zone_id="$(cf_get_zone_id "$Domain")"
  if [ -z "$zone_id" ]; then
    echo "CF: zone_id não encontrado para $Domain"
    return 1
  fi
  local rec_id; rec_id="$(cf_get_record_id "$zone_id" "$type" "$name")"
  local payload; payload="$(jq -cn --arg type "$type" --arg name "$name" --arg content "$content" --argjson ttl "$ttl" \
      '{type:$type,name:$name,content:$content,ttl:$ttl,proxied:false}')"
  if [ -n "$rec_id" ]; then
    _cf_api PUT "/zones/${zone_id}/dns_records/${rec_id}" "$payload" >/dev/null && echo "CF: atualizado ${type} ${name}"
  else
    _cf_api POST "/zones/${zone_id}/dns_records" "$payload" >/dev/null && echo "CF: criado ${type} ${name}"
  fi
}

# ==============================
#   PRE-CHECK & DEPENDÊNCIAS
# ==============================
require_root
if ! is_ubuntu; then echo "Aviso: Script otimizado para Ubuntu. Prosseguindo."; fi

apt_quick_install ca-certificates curl sed coreutils sudo gnupg lsb-release python3 jq software-properties-common
apt_quick_install postfix certbot python3-certbot-dns-cloudflare apache2
install_postfwd
POSTFWD_BIN="${POSTFWD_BIN:-$(command -v postfwd 2>/dev/null || command -v postfwd2 2>/dev/null || echo /usr/sbin/postfwd)}"
apt_quick_install opendkim opendkim-tools opendmarc python3-publicsuffix2

# ==============================
#   CERTBOT + CLOUDFLARE TOKEN
# ==============================
if [ -n "$CF_API_TOKEN" ]; then
  ensure_dir "$(dirname "$CF_SECRETS_FILE")" "root:root" 0700
  umask 077
  cat >"$CF_SECRETS_FILE" <<EOF
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
  chmod 600 "$CF_SECRETS_FILE"
fi
CFPY='/usr/lib/python3/dist-packages/CloudFlare/cloudflare.py'
if [ -f "$CFPY" ]; then
  sed -i "s/self\.email is ''/self.email == ''/g" "$CFPY" || true
  sed -i "s/self\.token is ''/self.token == ''/g" "$CFPY" || true
fi

# ==============================
#          DOMÍNIO
# ==============================
Domain="$(calc_domain)"; [ -n "$Domain" ] || { echo "Falha ao calcular Domain a partir de $ServerName"; exit 1; }
echo ">> ServerName: $ServerName | eTLD+1: $Domain | IP: $ServerIP"

# ==============================
#         OBTENÇÃO CERT
# ==============================
obtain_le_cert() {
  local have_token=0; [ -s "$CF_SECRETS_FILE" ] && have_token=1
  if [ "$have_token" -eq 1 ]; then
    echo ">> Tentando LE DNS-01 (Cloudflare) para: $ServerName e $Domain"
    certbot certonly --non-interactive --agree-tos -m "$ADMIN_EMAIL" \
      --dns-cloudflare --dns-cloudflare-credentials "$CF_SECRETS_FILE" \
      -d "$ServerName" -d "$Domain" || true
  else
    echo ">> Sem token Cloudflare; pulando LE (usará snakeoil)."
  fi
}
obtain_le_cert
LE_FULLCHAIN="/etc/letsencrypt/live/$ServerName/fullchain.pem"
LE_PRIVKEY="/etc/letsencrypt/live/$ServerName/privkey.pem"

# ==============================
#      POSTFIX (main.cf)
# ==============================
bk /etc/postfix/main.cf
if [ "$RECEIVE_SMTP" -eq 1 ]; then replace_or_add_postconf "inet_interfaces" "all"; else replace_or_add_postconf "inet_interfaces" "loopback-only"; fi
replace_or_add_postconf "mynetworks_style" "host"
replace_or_add_postconf "myhostname" "$ServerName"
replace_or_add_postconf "mydestination" "$ServerName, localhost"
replace_or_add_postconf "smtp_host_lookup" "dns, native"
replace_or_add_postconf "smtp_address_preference" "ipv4"
if [ -s "$LE_FULLCHAIN" ] && [ -s "$LE_PRIVKEY" ]; then
  echo ">> Postfix: usando Let's Encrypt"
  replace_or_add_postconf "smtpd_tls_cert_file" "$LE_FULLCHAIN"
  replace_or_add_postconf "smtpd_tls_key_file" "$LE_PRIVKEY"
else
  echo ">> Postfix: usando snakeoil"
  apt_quick_install ssl-cert
  replace_or_add_postconf "smtpd_tls_cert_file" "/etc/ssl/certs/ssl-cert-snakeoil.pem"
  replace_or_add_postconf "smtpd_tls_key_file" "/etc/ssl/private/ssl-cert-snakeoil.key"
fi
replace_or_add_postconf "smtpd_use_tls" "yes"
replace_or_add_postconf "smtp_tls_security_level" "may"
replace_or_add_postconf "smtpd_tls_security_level" "may"
replace_or_add_postconf "smtpd_sasl_auth_enable" "no"  # SASL global off; liga no submission se habilitar

# Integra Postfwd
NEEDED="check_policy_service inet:${POLICY_HOST}:${POLICY_PORT}"
CURRENT="$(postconf -h smtpd_recipient_restrictions 2>/dev/null || echo "")"
sanitize_csv() { echo "$1" | sed -E 's/[,[:space:]]+/, /g; s/^, //; s/, $//'; }
if ! echo "$CURRENT" | grep -q "$NEEDED"; then
  if [ -n "$CURRENT" ]; then NEW="$(sanitize_csv "${NEEDED}, ${CURRENT}")"; else NEW="$NEEDED"; fi
  replace_or_add_postconf "smtpd_recipient_restrictions" "$NEW"
fi

# ==============================
#       POSTFWD (policy)
# ==============================
ensure_dir /etc/postfwd "root:root" 0755
ensure_dir /var/lib/postfwd2 "postfix:postfix" 0755
ensure_dir /run/postfwd "postfix:postfix" 0755

cat >/etc/postfwd/postfwd.cf <<'EOF'
# /etc/postfwd/postfwd.cf
# =========================================
# BASE
# =========================================
id=RATELIMIT_BY_IP
  request=smtpd_access_policy
  protocol_state=RCPT
  protocol_name=SMTP
  client_address==~/.*/
  action=rate(client_address/60/60/100 "450 4.7.1 Too many rcpt per IP; try later")

id=LOCAL_NETS
  request=smtpd_access_policy
  client_address=127.0.0.1
  action=DUNNO

# =========================================
# LIMITES POR PROVEDOR
# =========================================
# Grandes provedores globais
id=limit-gmail;     recipient=~/.+@gmail\.com$/;                                      action=rate(recipient_domain/2000/3600/450 "4.7.1 Limite 2000/h atingido p/ Gmail")
id=limit-msn;       recipient=~/.+@(outlook\.com|hotmail\.com|live\.com|msn\.com)$/;  action=rate(recipient_domain/1000/86400/450 "4.7.1 Limite 1000/dia atingido p/ Microsoft")
id=limit-yahoo;     recipient=~/.+@yahoo\.(com|com\.br|com\.ar|com\.mx)$/;            action=rate(recipient_domain/150/3600/450 "4.7.1 Limite 150/h atingido p/ Yahoo")

# Provedores/hostings
id=limit-kinghost;  recipient=~/.+@kinghost\.net$/;                                   action=rate(recipient_domain/300/3600/450 "4.7.1 Limite 300/h atingido p/ KingHost")
id=limit-uol;       recipient=~/.+@uol\.com\.br$/;                                    action=rate(recipient_domain/300/3600/450 "4.7.1 Limite 300/h atingido p/ UOL")
id=limit-locaweb;   recipient=~/.+@locaweb\.com\.br$/;                                action=rate(recipient_domain/500/3600/450 "4.7.1 Limite 500/h atingido p/ Locaweb")
id=limit-mandic;    recipient=~/.+@mandic\.com\.br$/;                                 action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ Mandic")
id=limit-titan;     recipient=~/.+@titan\.email$/;                                    action=rate(recipient_domain/500/3600/450 "4.7.1 Limite 500/h atingido p/ Titan")
id=limit-godaddy;   recipient=~/.+@secureserver\.net$/;                               action=rate(recipient_domain/300/3600/450 "4.7.1 Limite 300/h atingido p/ GoDaddy")
id=limit-zimbra;    recipient=~/.+@zimbra\..+$/;                                      action=rate(recipient_domain/400/3600/450 "4.7.1 Limite 400/h atingido p/ Zimbra")
# id=limit-office365; recipient=~/.+@office365\.com$/; action=rate(recipient_domain/2000/3600/450 "4.7.1 Limite 2000/h atingido p/ Office365")

# Argentina
id=limit-fibertel;  recipient=~/.+@fibertel\.com\.ar$/;                               action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ Fibertel")
id=limit-speedy;    recipient=~/.+@speedy\.com\.ar$/;                                 action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ Speedy")
id=limit-personal;  recipient=~/.+@personal\.com\.ar$/;                               action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ Personal")
id=limit-telecom;   recipient=~/.+@telecom\.com\.ar$/;                                action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ Telecom")
id=limit-claro-ar;  recipient=~/.+@claro\.com\.ar$/;                                  action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ Claro AR")

# México
id=limit-telmex;    recipient=~/.+@prodigy\.net\.mx$/;                                action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ Telmex")
id=limit-axtel;     recipient=~/.+@axtel\.net$/;                                      action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ Axtel")
id=limit-izzi;      recipient=~/.+@izzi\.net\.mx$/;                                   action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ Izzi")
id=limit-megacable; recipient=~/.+@megacable\.com\.mx$/;                              action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ Megacable")
id=limit-totalplay; recipient=~/.+@totalplay\.net\.mx$/;                              action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ TotalPlay")
id=limit-telcel;    recipient=~/.+@telcel\.net$/;                                     action=rate(recipient_domain/200/3600/450 "4.7.1 Limite 200/h atingido p/ Telcel")

# Final
id=default;         recipient=~/.+/;                                                  action=DUNNO
EOF

cat >/etc/systemd/system/postfwd-local.service <<EOF
[Unit]
Description=postfwd policy daemon (local-only)
After=network-online.target postfix.service
Wants=network-online.target
Requires=postfix.service

[Service]
Type=forking
PermissionsStartOnly=true
ExecStartPre=/usr/bin/install -d -o postfix -g postfix -m 0755 /run/postfwd
ExecStartPre=/usr/bin/install -d -o postfix -g postfix -m 0755 /var/lib/postfwd2
ExecReload=/bin/kill -HUP \$MAINPID
User=postfix
Group=postfix
ExecStart=${POSTFWD_BIN} -u postfix -g postfix \
  --keep_rates --save_rates /var/lib/postfwd2/rates.db \
  --shortlog --summary=600 \
  --cache=600 --cache-rbl-timeout=3600 \
  --cleanup-requests=1200 --cleanup-rbls=1800 --cleanup-rates=1200 \
  --file=/etc/postfwd/postfwd.cf --interface=${POLICY_HOST} --port=${POLICY_PORT}
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now postfwd-local

# ==============================
#      OPEN-DKIM
# ==============================
bk /etc/opendkim.conf
bk /etc/default/opendkim
ensure_dir /etc/opendkim "opendkim:opendkim" 0755
ensure_dir /etc/opendkim/keys "opendkim:opendkim" 0755
ensure_dir "/etc/opendkim/keys/$Domain" "opendkim:opendkim" 0700
if [ ! -s "/etc/opendkim/keys/$Domain/${DKIM_SELECTOR}.private" ]; then
  echo ">> Gerando chave DKIM ${DKIM_BITS} (selector ${DKIM_SELECTOR})"
  ( cd "/etc/opendkim/keys/$Domain"
    opendkim-genkey -s "$DKIM_SELECTOR" -d "$Domain" -b "$DKIM_BITS" -r -v
    chown opendkim:opendkim "${DKIM_SELECTOR}.private" "${DKIM_SELECTOR}.txt"
    chmod 0600 "${DKIM_SELECTOR}.private" )
fi
cat >/etc/opendkim.conf <<EOF
Syslog                  yes
UMask                   002
Mode                    sv
Canonicalization        relaxed/simple
OversignHeaders         From
AutoRestart             yes
KeyTable                /etc/opendkim/KeyTable
SigningTable            /etc/opendkim/SigningTable
ExternalIgnoreList      /etc/opendkim/TrustedHosts
InternalHosts           /etc/opendkim/TrustedHosts
Socket                  inet:8891@127.0.0.1
EOF
cat >/etc/default/opendkim <<'EOF'
RUNDIR=/run/opendkim
SOCKET="inet:8891@127.0.0.1"
USER=opendkim
GROUP=opendkim
PIDFILE="$RUNDIR/opendkim.pid"
EXTRAAFTER=
EOF
cat >/etc/opendkim/TrustedHosts <<EOF
127.0.0.1
::1
$ServerIP
$ServerName
$Domain
EOF
cat >/etc/opendkim/KeyTable <<EOF
${DKIM_SELECTOR}._domainkey.${Domain} ${Domain}:${DKIM_SELECTOR}:/etc/opendkim/keys/${Domain}/${DKIM_SELECTOR}.private
EOF
cat >/etc/opendkim/SigningTable <<EOF
*@${Domain} ${DKIM_SELECTOR}._domainkey.${Domain}
EOF
systemctl enable --now opendkim

# ==============================
#      OPEN-DMARC
# ==============================
bk /etc/opendmarc.conf
bk /etc/default/opendmarc
cat >/etc/opendmarc.conf <<EOF
AuthservID              ${ServerName}
TrustedAuthservIDs      ${ServerName}
IgnoreAuthenticatedClients true
Syslog                  true
AutoRestart             true
Socket                  inet:8893@127.0.0.1
EOF
cat >/etc/default/opendmarc <<'EOF'
RUNDIR=/run/opendmarc
SOCKET="inet:8893@127.0.0.1"
USER=opendmarc
GROUP=opendmarc
PIDFILE="$RUNDIR/opendmarc.pid"
EXTRAAFTER=
EOF
systemctl enable --now opendmarc

# ==============================
#   Postfix ↔ DKIM/DMARC (milters)
# ==============================
replace_or_add_postconf "milter_protocol" "6"
replace_or_add_postconf "milter_default_action" "accept"
replace_or_add_postconf "smtpd_milters" "inet:127.0.0.1:8891, inet:127.0.0.1:8893"
replace_or_add_postconf "non_smtpd_milters" "inet:127.0.0.1:8891, inet:127.0.0.1:8893"

# ==============================
#      SUBMISSION/587 (opcional)
# ==============================
if [ "$ENABLE_SUBMISSION" -eq 1 ]; then
  echo ">> Habilitando SUBMISSION/587"
  postconf -M submission/inet='submission inet n       -       y       -       -       smtpd'
  postconf -P 'submission/inet/syslog_name=submission'
  postconf -P 'submission/inet/smtpd_tls_security_level=encrypt'
  postconf -P 'submission/inet/smtpd_sasl_auth_enable=yes'
  postconf -P 'submission/inet/milter_macro_daemon_name=ORIGINATING'
  postconf -P "submission/inet/smtpd_recipient_restrictions=permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination"
fi
systemctl reload postfix || systemctl restart postfix

# ==============================
#   PUBLICAR DNS (SPF/DKIM/DMARC)
# ==============================
build_spf() {
  local parts=("v=spf1")
  [ -n "$ServerIP" ] && parts+=("ip4:${ServerIP}")
  for ip in $SPF_EXTRA_IP4; do parts+=("ip4:${ip}"); done
  for a in $SPF_A_RECORDS; do parts+=("a:${a}"); done
  for inc in $SPF_INCLUDES; do parts+=("include:${inc}"); done
  if [ "$SPF_SOFTFAIL" = "1" ]; then parts+=("~all"); else parts+=("-all"); fi
  printf "%s " "${parts[@]}"
}
build_dmarc() {
  local parts=("v=DMARC1;" "p=${DMARC_POLICY};" "sp=${DMARC_SUBPOLICY};" "adkim=${DMARC_ADKIM};" "aspf=${DMARC_ASPF};" "pct=${DMARC_PCT}")
  [ -n "$DMARC_RUA" ] && parts+=("rua=mailto:${DMARC_RUA};")
  [ -n "$DMARC_RUF" ] && parts+=("ruf=mailto:${DMARC_RUF};")
  echo "${parts[@]}" | sed -E 's/; ;/;/g; s/; $//'
}
extract_dkim_txt() { awk -F'"' '/"/{for(i=2;i<=NF;i+=2)printf "%s",$i} END{print ""}' "/etc/opendkim/keys/$Domain/${DKIM_SELECTOR}.txt"; }

DNS_MANUAL_MSG=""
if command -v jq >/dev/null 2>&1 && [ -n "$CF_API_TOKEN" ]; then
  SPF_STR="$(build_spf)"; create_or_update_record "$Domain" "TXT" "$SPF_STR" "300" || DNS_MANUAL_MSG+="\nSPF ($Domain): $SPF_STR"
  DKIM_NAME="${DKIM_SELECTOR}._domainkey.${Domain}"; DKIM_STR="$(extract_dkim_txt)"
  if [ -n "$DKIM_STR" ]; then create_or_update_record "$DKIM_NAME" "TXT" "$DKIM_STR" "300" || DNS_MANUAL_MSG+="\nDKIM ($DKIM_NAME): $DKIM_STR"; else DNS_MANUAL_MSG+="\n[ERRO] Não consegui extrair o TXT DKIM"; fi
  DMARC_NAME="_dmarc.${Domain}"; DMARC_STR="$(build_dmarc)"; create_or_update_record "$DMARC_NAME" "TXT" "$DMARC_STR" "300" || DNS_MANUAL_MSG+="\nDMARC ($DMARC_NAME): $DMARC_STR"
else
  SPF_STR="$(build_spf)"; DKIM_NAME="${DKIM_SELECTOR}._domainkey.${Domain}"; DKIM_STR="$(extract_dkim_txt)"
  DMARC_NAME="_dmarc.${Domain}"; DMARC_STR="$(build_dmarc)"
  DNS_MANUAL_MSG+="\nSPF ($Domain): $SPF_STR"
  DNS_MANUAL_MSG+="\nDKIM ($DKIM_NAME): $DKIM_STR"
  DNS_MANUAL_MSG+="\nDMARC ($DMARC_NAME): $DMARC_STR"
fi

# ==============================
#      APACHE + VHOST SSL
# ==============================
a2enmod ssl headers rewrite >/dev/null 2>&1 || true
if [ -s "$LE_FULLCHAIN" ] && [ -s "$LE_PRIVKEY" ]; then AP_SSL_CERT="$LE_FULLCHAIN"; AP_SSL_KEY="$LE_PRIVKEY";
else AP_SSL_CERT="/etc/ssl/certs/ssl-cert-snakeoil.pem"; AP_SSL_KEY="/etc/ssl/private/ssl-cert-snakeoil.key"; apt_quick_install ssl-cert; fi
VHOST_FILE="/etc/apache2/sites-available/${ServerName}.conf"; bk "$VHOST_FILE"
cat >"$VHOST_FILE" <<EOF
<VirtualHost *:80>
  ServerName ${ServerName}
  Redirect permanent / https://${ServerName}/
</VirtualHost>

<VirtualHost *:443>
  ServerName ${ServerName}
  SSLEngine on
  SSLCertificateFile      ${AP_SSL_CERT}
  SSLCertificateKeyFile   ${AP_SSL_KEY}
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  DocumentRoot /var/www/html
  <Directory /var/www/html>
    AllowOverride All
    Require all granted
  </Directory>
  ErrorLog \${APACHE_LOG_DIR}/${ServerName}_error.log
  CustomLog \${APACHE_LOG_DIR}/${ServerName}_access.log combined
</VirtualHost>
EOF
a2ensite "${ServerName}.conf" >/dev/null 2>&1 || true
systemctl reload apache2 || systemctl restart apache2

# =====================================================================
# ================== APPLICATION: endereços de função ==================
# =====================================================================
add_alias() { local a="$1" b="$2"; grep -qiE "^\s*${a}:" /etc/aliases 2>/dev/null || echo "${a}: ${b}" >> /etc/aliases; }
echo "Configurando aliases locais (outbound-only) para $ServerName..."
[ -f /etc/aliases ] || : > /etc/aliases
add_alias "postmaster" "${POSTMASTER_DEST}"
add_alias "abuse"      "${POSTMASTER_DEST}"
add_alias "support"    "${SUPPORT_DEST}"
add_alias "contacto"   "${SUPPORT_DEST}"
add_alias "dmarc-reports" "${POSTMASTER_DEST}"

UNSUB_SCRIPT="/usr/local/bin/unsub_capture.sh"
if [ ! -x "$UNSUB_SCRIPT" ]; then
  apt_wait 900; apt-get install -y procmail >/dev/null 2>&1 || true
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

if [ "${DESCARTAR_NOREPLY}" = "true" ]; then add_alias "noreply" "/dev/null"; else add_alias "noreply" "root"; fi

BNC_SCRIPT="/usr/local/bin/bounce_capture.sh"
if [ ! -x "$BNC_SCRIPT" ]; then
  apt_wait 900; apt-get install -y procmail >/dev/null 2>&1 || true
  cat > "$BNC_SCRIPT" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
LOGDIR="/var/log/bounce"
LIST="$LOGDIR/bounces.log"
mkdir -p "$LOGDIR"
RP="$(/usr/bin/formail -xReturn-Path: 2>/dev/null | tr -d '<>\r' | tail -n1 || true)"

TAG=""
if [[ "${RP:-}" =~ ^bounce\+([A-Za-z0-9._-]+)@ ]]; then TAG="${BASH_REMATCH[1]}"; fi

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
newaliases || true

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
install -d -m 755 /var/log/bounce /var/log/unsub
touch /var/log/bounce/bounces.log /var/log/unsub/unsubscribed.txt
chown -R www-data:www-data /var/log/unsub
chown root:adm /var/log/bounce/bounces.log || true
chmod 640 /var/log/bounce/bounces.log /var/log/unsub/unsubscribed.txt || true

systemctl reload postfix || true

# ==============================
#        STATUS RESUMO
# ==============================
echo "-------------------------------------------"
echo " Postfix           : $(systemctl is-active postfix || true)"
echo " Postfwd           : $(systemctl is-active postfwd-local || true)"
echo " OpenDKIM          : $(systemctl is-active opendkim || true)"
echo " OpenDMARC         : $(systemctl is-active opendmarc || true)"
echo " Apache            : $(systemctl is-active apache2 || true)"
echo " Cert LE           : $([ -s "$LE_FULLCHAIN" ] && echo 'OK' || echo 'snakeoil')"
echo " Submission/587    : $([ "$ENABLE_SUBMISSION" -eq 1 ] && echo 'habilitado' || echo 'desabilitado')"
echo " Receber :25       : $([ "$RECEIVE_SMTP" -eq 1 ] && echo 'all' || echo 'loopback-only')"
echo " Vhost SSL         : $VHOST_FILE"
echo " DKIM selector     : $DKIM_SELECTOR"
echo " DKIM key (priv)   : /etc/opendkim/keys/$Domain/${DKIM_SELECTOR}.private"
echo "-------------------------------------------"
if [ -n "$DNS_MANUAL_MSG" ]; then
  echo ">> Publique manualmente os TXT na zona do $Domain:"
  echo -e "$DNS_MANUAL_MSG"
else
  echo ">> DNS SPF/DKIM/DMARC publicados/atualizados via Cloudflare (se token presente)."
fi

echo "================================= Todos os comandos foram executados com sucesso! ==================================="
echo "======================================================= FIM =========================================================="
echo "================================================= Reiniciar servidor ================================================="
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
