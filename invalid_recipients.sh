#!/usr/bin/env bash
# deploy-classify-bounces.sh
set -euo pipefail

HOSTS_FILE="${1:-vps_list.txt}"
SSH_KEY="${2:-}"
DEFAULT_PORT=22
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
[ -n "${SSH_KEY}" ] && SSH_OPTS+=(-i "${SSH_KEY}")

if [ ! -f "${HOSTS_FILE}" ]; then
  echo "Arquivo de hosts não encontrado: ${HOSTS_FILE}" >&2
  exit 1
fi

install_remote() {
  local target="$1" port="$2"
  echo ">>> [${target}:${port}] Iniciando instalação..."

  ssh "${SSH_OPTS[@]}" -p "${port}" "${target}" 'bash -seu -o pipefail' <<'REMOTE'
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "[ERRO] Não é root e 'sudo' não está instalado." >&2
    exit 1
  fi
fi

# Função para instalar dependências (tenta apt, dnf, yum, zypper)
install_deps() {
  # util-linux (flock) e gzip (zgrep)
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -qq || true
    $SUDO apt-get install -y -qq util-linux gzip || true
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y util-linux gzip || true
  elif command -v yum >/dev/null 2>&1; then
    $SUDO yum install -y util-linux gzip || true
  elif command -v zypper >/dev/null 2>&1; then
    $SUDO zypper -n install util-linux gzip || true
  fi
}

install_deps

# Cria o script exatamente como solicitado
$SUDO bash -seu -o pipefail <<'INNER'
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
INNER

echo "[OK] Script instalado e sudoers configurado."
REMOTE

  echo ">>> [${target}:${port}] Concluído."
}

# Lê o arquivo de hosts
while IFS= read -r line; do
  # Ignora linhas vazias/comentários
  [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

  entry="${line// /}"
  hostpart="$entry"
  port="$DEFAULT_PORT"

  # Permite user@host:port
  if [[ "$entry" == *:* ]]; then
    hostpart="${entry%%:*}"
    port="${entry##*:}"
  fi

  install_remote "$hostpart" "$port" || echo "[FALHA] ${hostpart}:${port}"
done < "${HOSTS_FILE}"
