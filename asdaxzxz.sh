#!/usr/bin/env bash
set -Eeuo pipefail

echo "[1/8] Root check..."
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."; exit 1
fi
export DEBIAN_FRONTEND=noninteractive

echo "[2/8] Dependências básicas..."
apt-get update -y
apt-get install -y curl ca-certificates grep sed iproute2 iputils-ping

echo "[3/8] postfwd..."
apt-get install -y postfwd

# Descobre binário (alguns sistemas têm /usr/sbin/postfwd2, outros só /usr/sbin/postfwd)
POSTFWD_BIN="$(command -v postfwd2 || command -v postfwd || true)"
if [ -z "${POSTFWD_BIN}" ]; then
  echo "ERRO: postfwd não encontrado após instalação."; exit 1
fi
echo "Usando binário: ${POSTFWD_BIN}"

echo "[4/8] Regras em /etc/postfwd/postfwd.cf (1 linha por regra)..."
install -d -m 0755 /etc/postfwd
cat >/etc/postfwd/postfwd.cf <<'EOF'
# ===== LIMITES POR PROVEDOR (1 linha por regra) =====
id=limit-kinghost   pattern=recipient mx=.*kinghost\.net        action=rate(global/300/3600) defer_if_permit "Limite de 300/h p/ KingHost."
id=limit-uolhost    pattern=recipient mx=.*uhserver              action=rate(global/300/3600) defer_if_permit "Limite de 300/h p/ UOL Host."
id=limit-locaweb    pattern=recipient mx=.*locaweb\.com\.br      action=rate(global/500/3600) defer_if_permit "Limite de 500/h p/ Locaweb."
id=limit-yahoo      pattern=recipient mx=.*yahoo\.com            action=rate(global/150/3600) defer_if_permit "Limite de 150/h p/ Yahoo."
id=limit-mandic     pattern=recipient mx=.*mandic\.com\.br       action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Mandic."
id=limit-titan      pattern=recipient mx=.*titan\.email          action=rate(global/500/3600) defer_if_permit "Limite de 500/h p/ Titan."
id=limit-google     pattern=recipient mx=.*google                action=rate(global/2000/3600) defer_if_permit "Limite de 2000/h p/ Google."
id=limit-hotmail    pattern=recipient mx=.*hotmail\.com          action=rate(global/1000/86400) defer_if_permit "Limite de 1000/dia p/ Hotmail."
id=limit-office365  pattern=recipient mx=.*outlook\.com          action=rate(global/2000/3600) defer_if_permit "Limite de 2000/h p/ Office 365."
id=limit-godaddy    pattern=recipient mx=.*secureserver\.net     action=rate(global/300/3600) defer_if_permit "Limite de 300/h p/ GoDaddy."
id=limit-zimbra     pattern=recipient mx=.*zimbra                action=rate(global/400/3600) defer_if_permit "Limite de 400/h p/ Zimbra."
# Argentina
id=limit-fibertel   pattern=recipient mx=.*fibertel\.com\.ar     action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Fibertel."
id=limit-speedy     pattern=recipient mx=.*speedy\.com\.ar       action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Speedy."
id=limit-personal   pattern=recipient mx=.*personal\.com\.ar     action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Personal."
id=limit-telecom    pattern=recipient mx=.*telecom\.com\.ar      action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Telecom."
id=limit-claro-ar   pattern=recipient mx=.*claro\.com\.ar        action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Claro AR."
# México
id=limit-telmex     pattern=recipient mx=.*prodigy\.net\.mx      action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Telmex."
id=limit-axtel      pattern=recipient mx=.*axtel\.net            action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Axtel."
id=limit-izzi       pattern=recipient mx=.*izzi\.net\.mx         action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Izzi."
id=limit-megacable  pattern=recipient mx=.*megacable\.com\.mx    action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Megacable."
id=limit-totalplay  pattern=recipient mx=.*totalplay\.net\.mx    action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ TotalPlay."
id=limit-telcel     pattern=recipient mx=.*telcel\.net           action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Telcel."
# Catch-all
id=no-limit         pattern=recipient mx=.*                      action=permit
EOF
chmod 0644 /etc/postfwd/postfwd.cf

echo "[5/8] Desabilitando o SysV do pacote (pra sumir o update-rc.d error)..."
systemctl stop postfwd 2>/dev/null || true
systemctl disable postfwd 2>/dev/null || true
systemctl mask postfwd 2>/dev/null || true

echo "[6/8] Service nativo (forking, com PID em /run/postfwd)..."
cat >/etc/systemd/system/postfwd-local.service <<EOF
[Unit]
Description=postfwd policy daemon (local-only)
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
# Garante diretório de PID com permissão pro usuário do serviço
ExecStartPre=/bin/mkdir -p /run/postfwd
ExecStartPre=/bin/chown postfix:postfix /run/postfwd
PIDFile=/run/postfwd/postfwd.pid
# Inicia em modo daemon (sem --nodaemon), só no loopback:10045
ExecStart=/bin/sh -c '${POSTFWD_BIN} --shortlog --summary=600 \
  --cache=600 --cache-rbl-timeout=3600 \
  --cleanup-requests=1200 --cleanup-rbls=1800 --cleanup-rates=1200 \
  --file=/etc/postfwd/postfwd.cf --interface=127.0.0.1 --port=10045'
Restart=on-failure
User=postfix
Group=postfix

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now postfwd-local

echo "[7/8] Integração no Postfix (adiciona policy se faltar)..."
NEEDED='check_policy_service inet:127.0.0.1:10045'
CURRENT="$(postconf -h smtpd_recipient_restrictions || true)"
if [ -z "$CURRENT" ]; then
  postconf -e "smtpd_recipient_restrictions=permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_unauth_destination, reject_unlisted_recipient, ${NEEDED}"
else
  if ! echo "$CURRENT" | grep -qF "$NEEDED"; then
    postconf -e "smtpd_recipient_restrictions=${CURRENT}, ${NEEDED}"
  fi
fi
systemctl restart postfix

echo "[8/8] Health-check..."
echo "---- postfwd-local status ----"
systemctl status postfwd-local --no-pager -l || true
echo "---- porta 10045 (loopback) ----"
ss -ltnp | grep 10045 || true
echo "---- postfix conf ----"
postconf -n | egrep 'smtpd_recipient_restrictions|check_policy_service' || true
echo "---- logs (últimas 40 linhas) ----"
journalctl -u postfwd-local -n 40 --no-pager || true

echo "OK: postfwd em modo daemon (rate() ativo), ouvindo 127.0.0.1:10045."
