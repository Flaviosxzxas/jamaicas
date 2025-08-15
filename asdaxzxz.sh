#!/bin/bash
set -euo pipefail

# ============================================
# 1) Root check
# ============================================
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# ============================================
# 2) Dependências básicas (sem 'awk')
# ============================================
apt-get update -y
apt-get install -y curl ca-certificates grep sed iproute2 iputils-ping

# ============================================
# 3) Instalar postfwd
# ============================================
echo "[postfwd] Instalando…"
apt-get install -y postfwd

PFWBIN="$(command -v postfwd3 || command -v postfwd2 || command -v postfwd || true)"
if [ -z "$PFWBIN" ]; then
  echo "[postfwd] ERRO: binário não encontrado após instalação."
  exit 1
fi

# ============================================
# 4) Gravar /etc/postfwd/postfwd.cf
# ============================================
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

# ============================================
# 5) Unit file systemd nativo (evita update-rc.d)
# ============================================
cat > /etc/systemd/system/postfwd.service <<EOF
[Unit]
Description=postfwd policy daemon (local-only)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PFWBIN --nodaemon --shortlog --summary=600 --cache=600 --cache-rbl-timeout=3600 --cleanup-requests=1200 --cleanup-rbls=1800 --cleanup-rates=1200 --file=$PFWCFG --interface=127.0.0.1 --port=10045
Restart=on-failure
User=postfix
Group=postfix

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now postfwd

# ============================================
# 6) Integrar no Postfix (se ainda não tiver)
# ============================================
NEEDED='check_policy_service inet:127.0.0.1:10045'
CURRENT="$(postconf -h smtpd_recipient_restrictions || true)"

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

# ============================================
# 7) Healthcheck
# ============================================
echo "[health] postfwd:"
systemctl --no-pager --full status postfwd | sed -n '1,25p' || true

echo "[health] porta 10045 (loopback):"
ss -ltnp | grep -E '127\.0\.0\.1:10045' || true

echo "[health] postfix conf (recipients):"
postconf -n | grep -E '^smtpd_recipient_restrictions|^smtpd_milters|^non_smtpd_milters' || true

echo "[ok] postfwd integrado ao Postfix (loopback only). Sem abrir recepção externa."
