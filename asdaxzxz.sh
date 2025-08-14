#!/usr/bin/env bash
set -Eeuo pipefail

# ========= cabeçalho p/ log e "hold" sem alterar seu .js =========
HOLD_SECS="${HOLD_SECS:-240}"   # quanto tempo segurar no final se não houver TTY
NO_HOLD="${NO_HOLD:-}"          # se NO_HOLD=1, não segura

LOG="/var/log/$(basename "$0")-$(date -u +%F_%H%M%S).log"
mkdir -p /var/log
exec > >(stdbuf -oL awk '{ print strftime("[%Y-%m-%d %H:%M:%S]"), $0 }' | tee -a "$LOG") 2>&1

finish() {
  rc=$?
  echo
  echo "==== FIM (rc=$rc) | log: $LOG ===="
  [ -n "$NO_HOLD" ] && exit "$rc"
  if tty -s; then
    echo "Pressione ENTER para fechar..."
    # shellcheck disable=SC2162
    read _
  else
    echo "Sem TTY; mantendo aberto por ${HOLD_SECS}s..."
    sleep "$HOLD_SECS"
  fi
  exit "$rc"
}
trap finish EXIT

# ===================== 1) root check =====================
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold")

# ===================== 2) deps básicas ====================
echo "[deps] Atualizando índices..."
apt-get update -y
echo "[deps] Instalando utilitários..."
apt-get install "${APT_OPTS[@]}" curl ca-certificates grep sed gawk iproute2 iputils-ping >/dev/null

# ===================== 3) postfwd ========================
echo "[postfwd] Instalando pacote..."
apt-get install "${APT_OPTS[@]}" postfwd >/dev/null 2>&1 || \
apt-get install "${APT_OPTS[@]}" postfwd2 >/dev/null 2>&1 || \
apt-get install "${APT_OPTS[@]}" postfwd3 >/dev/null 2>&1 || true

PFWBIN="$(command -v postfwd || command -v postfwd2 || command -v postfwd3 || true)"
if [ -z "$PFWBIN" ]; then
  echo "[postfwd] ERRO: nenhum binário postfwd* encontrado após instalação."
  exit 1
fi
echo "[postfwd] Binário: $PFWBIN"

# ===================== 4) /etc/postfwd/postfwd.cf =========
mkdir -p /etc/postfwd
PFWCFG="/etc/postfwd/postfwd.cf"
cat > "$PFWCFG" <<'EOF'
# ==== LIMITES POR PROVEDOR (ajuste as taxas conforme sua realidade) =====
# Sintaxe: action=rate(<bucket>/<limite>/<janela_em_segundos>) defer_if_permit "mensagem"

id=limit-kinghost
pattern=recipient mx=.*kinghost\.net
action=rate(global/300/3600) defer_if_permit "Limite de 300/h atingido p/ KingHost."

id=limit-uolhost
pattern=recipient mx=.*uhserver
action=rate(global/300/3600) defer_if_permit "Limite de 300/h atingido p/ UOL Host."

id=limit-locaweb
pattern=recipient mx=.*locaweb\.com\.br
action=rate(global/500/3600) defer_if_permit "Limite de 500/h atingido p/ LocaWeb."

id=limit-yahoo
pattern=recipient mx=.*yahoo\.com
action=rate(global/150/3600) defer_if_permit "Limite de 150/h atingido p/ Yahoo."

id=limit-mandic
pattern=recipient mx=.*mandic\.com\.br
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ Mandic."

id=limit-titan
pattern=recipient mx=.*titan\.email
action=rate(global/500/3600) defer_if_permit "Limite de 500/h atingido p/ Titan."

id=limit-google
pattern=recipient mx=.*google
action=rate(global/2000/3600) defer_if_permit "Limite de 2000/h atingido p/ Google."

id=limit-hotmail
pattern=recipient mx=.*hotmail\.com
action=rate(global/1000/86400) defer_if_permit "Limite de 1000/dia atingido p/ Hotmail."

id=limit-office365
pattern=recipient mx=.*outlook\.com
action=rate(global/2000/3600) defer_if_permit "Limite de 2000/h atingido p/ Office 365."

id=limit-secureserver
pattern=recipient mx=.*secureserver\.net
action=rate(global/300/3600) defer_if_permit "Limite de 300/h atingido p/ GoDaddy."

id=limit-zimbra
pattern=recipient mx=.*zimbra
action=rate(global/400/3600) defer_if_permit "Limite de 400/h atingido p/ Zimbra."

# Argentina
id=limit-fibertel
pattern=recipient mx=.*fibertel\.com\.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ Fibertel."

id=limit-speedy
pattern=recipient mx=.*speedy\.com\.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ Speedy."

id=limit-personal
pattern=recipient mx=.*personal\.com\.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ Personal."

id=limit-telecom
pattern=recipient mx=.*telecom\.com\.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ Telecom."

id=limit-claro-ar
pattern=recipient mx=.*claro\.com\.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ Claro AR."

# México
id=limit-telmex
pattern=recipient mx=.*prodigy\.net\.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ Telmex."

id=limit-axtel
pattern=recipient mx=.*axtel\.net
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ Axtel."

id=limit-izzi
pattern=recipient mx=.*izzi\.net\.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ Izzi."

id=limit-megacable
pattern=recipient mx=.*megacable\.com\.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ Megacable."

id=limit-totalplay
pattern=recipient mx=.*totalplay\.net\.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ TotalPlay."

id=limit-telcel
pattern=recipient mx=.*telcel\.net
action=rate(global/200/3600) defer_if_permit "Limite de 200/h atingido p/ Telcel."

# ===== CATCH-ALL: o que não casou acima segue permitido =====
id=no-limit
pattern=recipient mx=.*
action=permit
EOF
chmod 0644 "$PFWCFG"
echo "[postfwd] Regras gravadas em $PFWCFG"

# ===================== 5) override do systemd =============
mkdir -p /etc/systemd/system/postfwd.service.d
cat > /etc/systemd/system/postfwd.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=$PFWBIN --nodaemon --shortlog --summary=600 --cache=600 --cache-rbl-timeout=3600 --cleanup-requests=1200 --cleanup-rbls=1800 --cleanup-rates=1200 --file=$PFWCFG --interface=127.0.0.1 --port=10045
EOF

systemctl daemon-reload
systemctl enable --now postfwd
systemctl restart postfwd

# ===================== 6) integrar no Postfix =============
NEEDED='check_policy_service inet:127.0.0.1:10045'
CURRENT="$(postconf -h smtpd_recipient_restrictions 2>/dev/null | tr -d '\n' || true)"

if [ -z "$CURRENT" ]; then
  echo "[postfix] smtpd_recipient_restrictions vazio — criando baseline + policy"
  postconf -e "smtpd_recipient_restrictions=permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_unauth_destination, reject_unlisted_recipient, ${NEEDED}"
else
  echo "[postfix] smtpd_recipient_restrictions atual: $CURRENT"
  if ! echo "$CURRENT" | grep -qF "$NEEDED"; then
    echo "[postfix] adicionando policy service ao final…"
    postconf -e "smtpd_recipient_restrictions=${CURRENT}, ${NEEDED}"
  else
    echo "[postfix] policy service já presente."
  fi
fi

systemctl restart postfix

# ===================== 7) healthcheck =====================
echo "[health] status postfwd:"
systemctl --no-pager --full status postfwd | sed -n '1,25p' || true

echo "[health] porta 127.0.0.1:10045:"
ss -ltnp | grep -E '127\.0\.0\.1:10045' || { echo "NÃO está em LISTEN"; true; }

echo "[health] postfix conf:"
postconf -n | grep -E '^(smtpd_recipient_restrictions|smtpd_milters|non_smtpd_milters)'

echo "[ok] postfwd integrado ao Postfix (loopback)."
