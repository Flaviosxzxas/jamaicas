#!/bin/bash
set -Eeuo pipefail

# =============================================================================
# postfwd + Postfix integration (systemd native) — idempotente
# =============================================================================

# 0) Root check
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
HOLD_SECS="${HOLD_SECS:-120}"   # quanto tempo segurar aberto sem TTY, p/ ver logs

# 1) Dependências básicas
echo "[deps] Atualizando índice e instalando requisitos…"
apt-get update -y
apt-get install -y curl ca-certificates grep sed awk iproute2 iputils-ping >/dev/null

# 2) Instalar postfwd
echo "[postfwd] Instalando pacote…"
apt-get install -y postfwd >/dev/null || {
  echo "[postfwd] ERRO: não consegui instalar o pacote 'postfwd'."
  exit 1
}

# 3) Descobrir binário (postfwd, postfwd2, postfwd3)
PFWBIN="$(command -v postfwd3 || true)"
[ -x "$PFWBIN" ] || PFWBIN="$(command -v postfwd2 || true)"
[ -x "$PFWBIN" ] || PFWBIN="$(command -v postfwd  || true)"
if [ -z "${PFWBIN:-}" ] || [ ! -x "$PFWBIN" ]; then
  echo "[postfwd] ERRO: binário não encontrado após instalação."
  exit 1
fi
echo "[postfwd] Binário: $PFWBIN"

# 4) Gravar regras em /etc/postfwd/postfwd.cf (idempotente)
install -d -m 0755 /etc/postfwd
PFWCFG="/etc/postfwd/postfwd.cf"
cat >"$PFWCFG" <<'EOF'
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
pattern=recipient mx=.**
action=permit
EOF
chmod 0644 "$PFWCFG"
echo "[postfwd] Regras gravadas em $PFWCFG"

# 5) Criar unit nativa systemd: /etc/systemd/system/postfwd.service
UNIT="/etc/systemd/system/postfwd.service"
cat >"$UNIT" <<EOF
[Unit]
Description=Postfix Policy Daemon (postfwd)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$PFWBIN --nodaemon --shortlog --summary=600 --cache=600 --cache-rbl-timeout=3600 \
  --cleanup-requests=1200 --cleanup-rbls=1800 --cleanup-rates=1200 \
  --file=$PFWCFG --interface=127.0.0.1 --port=10045
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "$UNIT"
systemctl daemon-reload

# 5.1) (Opcional) Silenciar compatibilidade SysV, se existir /etc/init.d/postfwd sem LSB
if [ -x /etc/init.d/postfwd ]; then
  if ! awk '/^### BEGIN INIT INFO/,/^### END INIT INFO/' /etc/init.d/postfwd | grep -q 'Default-Start:'; then
    echo "[compat] Injetando cabeçalho LSB no /etc/init.d/postfwd (para evitar update-rc.d erro)…"
    tmp="$(mktemp)"
    awk 'NR==1 {
            print $0
            print "### BEGIN INIT INFO"
            print "# Provides:          postfwd"
            print "# Required-Start:    $remote_fs $network"
            print "# Required-Stop:     $remote_fs $network"
            print "# Default-Start:     2 3 4 5"
            print "# Default-Stop:      0 1 6"
            print "# Short-Description: Postfix policy daemon"
            print "### END INIT INFO"
            next
         } {print}' /etc/init.d/postfwd >"$tmp" && cat "$tmp" > /etc/init.d/postfwd && rm -f "$tmp"
    chmod +x /etc/init.d/postfwd
    update-rc.d postfwd defaults || true
  fi
fi

# 6) Habilitar e iniciar a unit nativa
echo "[systemd] Habilitando e iniciando postfwd.service…"
systemctl enable --now postfwd.service

# 7) Integrar no Postfix (só adiciona policy se faltar)
NEEDED='check_policy_service inet:127.0.0.1:10045'
CURRENT="$(postconf -h smtpd_recipient_restrictions || true)"
if [ -z "$CURRENT" ]; then
  echo "[postfix] smtpd_recipient_restrictions vazio — criando baseline + policy"
  postconf -e "smtpd_recipient_restrictions=permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_unauth_destination, reject_unlisted_recipient, ${NEEDED}"
elif ! echo "$CURRENT" | grep -qF "$NEEDED"; then
  echo "[postfix] adicionando policy service ao final de smtpd_recipient_restrictions…"
  postconf -e "smtpd_recipient_restrictions=${CURRENT}, ${NEEDED}"
else
  echo "[postfix] policy service já presente em smtpd_recipient_restrictions."
fi

systemctl restart postfix

# 8) Healthcheck rápido
echo
echo "==================== HEALTHCHECK ===================="
echo "[status] postfwd.service:"
systemctl --no-pager --full status postfwd.service | sed -n '1,20p' || true
echo
echo "[listen] porta 10045 em loopback:"
ss -ltnp | grep -E '127\.0\.0\.1:10045' || echo "(!) nada ouvindo em 127.0.0.1:10045"
echo
echo "[postfix] conf relevante:"
postconf -n | grep -E '^smtpd_recipient_restrictions|^smtpd_milters|^non_smtpd_milters' || true
echo "====================================================="
echo

# 9) Segura aberto se não houver TTY (útil quando rodado via ssh sem interação)
if [ -t 0 ]; then
  read -rp "Pressione ENTER para sair… " _ || true
else
  echo "Sem TTY; mantendo aberto por ${HOLD_SECS}s para você ver os logs…"
  sleep "$HOLD_SECS" || true
fi
