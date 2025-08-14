#!/usr/bin/env bash
set -Eeuo pipefail

# ===== Log + hold para seu runner via SSH =====
HOLD_SECS="${HOLD_SECS:-240}"
NO_HOLD="${NO_HOLD:-}"
LOG="/var/log/$(basename "$0")-$(date -u +%F_%H%M%S).log"
mkdir -p /var/log
exec > >(stdbuf -oL awk '{ print strftime("[%Y-%m-%d %H:%M:%S]"), $0 }' | tee -a "$LOG") 2>&1
finish(){ rc=$?; echo; echo "==== FIM (rc=$rc) | log: $LOG ===="; [ -n "$NO_HOLD" ] && exit "$rc"; if tty -s; then echo "Pressione ENTER para fechar..."; read -r _; else echo "Sem TTY; mantendo aberto por ${HOLD_SECS}s..."; sleep "$HOLD_SECS"; fi; exit "$rc"; }
trap finish EXIT

# ===== Root =====
if [ "$(id -u)" -ne 0 ]; then echo "Este script precisa ser executado como root."; exit 1; fi
export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold")

echo "[deps] apt update..."
apt-get update -y
echo "[deps] utilitários..."
apt-get install "${APT_OPTS[@]}" curl ca-certificates grep gawk sed iproute2 iputils-ping >/dev/null

# ===== 1) Unit nativa ANTES da instalação (evita update-rc.d) =====
UNIT=/etc/systemd/system/postfwd.service
PFWCFG=/etc/postfwd/postfwd.cf
cat > "$UNIT" <<EOF
[Unit]
Description=Postfix Policy Daemon (postfwd)
After=network.target
Wants=network.target

[Service]
Type=simple
# Usamos /usr/bin/env para não depender de caminho exato antes do pacote existir
ExecStart=/usr/bin/env postfwd --nodaemon --shortlog --summary=600 --cache=600 --cache-rbl-timeout=3600 \\
  --cleanup-requests=1200 --cleanup-rbls=1800 --cleanup-rates=1200 \\
  --file=$PFWCFG --interface=127.0.0.1 --port=10045
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"
systemctl daemon-reload

# ===== 2) Bloquear start automático durante instalação =====
# (o pós-instalação pode tentar 'start'; a gente bloqueia e tira depois)
cat >/usr/sbin/policy-rc.d <<'EOF'
#!/bin/sh
exit 101
EOF
chmod +x /usr/sbin/policy-rc.d

# ===== 3) Instalar postfwd (pacote que sua distro tiver) =====
echo "[postfwd] instalando pacote..."
if ! apt-get install "${APT_OPTS[@]}" postfwd >/dev/null 2>&1; then
  apt-get install "${APT_OPTS[@]}" postfwd2 >/dev/null 2>&1 || \
  apt-get install "${APT_OPTS[@]}" postfwd3 >/dev/null 2>&1
fi

# libera start novamente
rm -f /usr/sbin/policy-rc.d || true

# ===== 4) Regras =====
mkdir -p /etc/postfwd
cat > "$PFWCFG" <<'EOF'
# ==== LIMITES POR PROVEDOR (ajuste as taxas conforme sua realidade) =====
# action=rate(<bucket>/<limite>/<janela_s>) defer_if_permit "mensagem"

id=limit-kinghost
pattern=recipient mx=.*kinghost\.net
action=rate(global/300/3600) defer_if_permit "Limite de 300/h p/ KingHost."

id=limit-uolhost
pattern=recipient mx=.*uhserver
action=rate(global/300/3600) defer_if_permit "Limite de 300/h p/ UOL Host."

id=limit-locaweb
pattern=recipient mx=.*locaweb\.com\.br
action=rate(global/500/3600) defer_if_permit "Limite de 500/h p/ LocaWeb."

id=limit-yahoo
pattern=recipient mx=.*yahoo\.com
action=rate(global/150/3600) defer_if_permit "Limite de 150/h p/ Yahoo."

id=limit-mandic
pattern=recipient mx=.*mandic\.com\.br
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Mandic."

id=limit-titan
pattern=recipient mx=.*titan\.email
action=rate(global/500/3600) defer_if_permit "Limite de 500/h p/ Titan."

id=limit-google
pattern=recipient mx=.*google
action=rate(global/2000/3600) defer_if_permit "Limite de 2000/h p/ Google."

id=limit-hotmail
pattern=recipient mx=.*hotmail\.com
action=rate(global/1000/86400) defer_if_permit "Limite de 1000/dia p/ Hotmail."

id=limit-office365
pattern=recipient mx=.*outlook\.com
action=rate(global/2000/3600) defer_if_permit "Limite de 2000/h p/ Office 365."

id=limit-secureserver
pattern=recipient mx=.*secureserver\.net
action=rate(global/300/3600) defer_if_permit "Limite de 300/h p/ GoDaddy."

id=limit-zimbra
pattern=recipient mx=.*zimbra
action=rate(global/400/3600) defer_if_permit "Limite de 400/h p/ Zimbra."

# Argentina
id=limit-fibertel
pattern=recipient mx=.*fibertel\.com\.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Fibertel."

id=limit-speedy
pattern=recipient mx=.*speedy\.com\.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Speedy."

id=limit-personal
pattern=recipient mx=.*personal\.com\.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Personal."

id=limit-telecom
pattern=recipient mx=.*telecom\.com\.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Telecom."

id=limit-claro-ar
pattern=recipient mx=.*claro\.com\.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Claro AR."

# México
id=limit-telmex
pattern=recipient mx=.*prodigy\.net\.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Telmex."

id=limit-axtel
pattern=recipient mx=.*axtel\.net
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Axtel."

id=limit-izzi
pattern=recipient mx=.*izzi\.net\.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Izzi."

id=limit-megacable
pattern=recipient mx=.*megacable\.com\.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Megacable."

id=limit-totalplay
pattern=recipient mx=.*totalplay\.net\.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ TotalPlay."

id=limit-telcel
pattern=recipient mx=.*telcel\.net
action=rate(global/200/3600) defer_if_permit "Limite de 200/h p/ Telcel."

# Catch-all
id=no-limit
pattern=recipient mx=.*
action=permit
EOF
chmod 0644 "$PFWCFG"

# ===== 5) (Re)carrega e habilita a nossa unit =====
systemctl daemon-reload
systemctl enable --now postfwd.service
systemctl restart postfwd.service || true

# ===== 6) Integra Postfix (só adiciona se faltar) =====
NEEDED='check_policy_service inet:127.0.0.1:10045'
CURRENT="$(postconf -h smtpd_recipient_restrictions 2>/dev/null | tr -d '\n' || true)"
if [ -z "$CURRENT" ]; then
  echo "[postfix] criando baseline + policy"
  postconf -e "smtpd_recipient_restrictions=permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_unauth_destination, reject_unlisted_recipient, ${NEEDED}"
elif ! echo "$CURRENT" | grep -qF "$NEEDED"; then
  echo "[postfix] adicionando policy ao final"
  postconf -e "smtpd_recipient_restrictions=${CURRENT}, ${NEEDED}"
else
  echo "[postfix] policy já presente"
fi
systemctl restart postfix

# ===== 7) Health =====
echo "[health] systemctl status postfwd (cabeçalho):"
systemctl --no-pager --full status postfwd | sed -n '1,25p' || true
echo "[health] listen 127.0.0.1:10045:"
ss -ltnp | grep -E '127\.0\.0\.1:10045' || echo "não está em LISTEN"
echo "[health] postfix conf:"
postconf -n | grep -E '^(smtpd_recipient_restrictions|smtpd_milters|non_smtpd_milters)'
