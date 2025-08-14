#!/bin/bash

 ============================================
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
# ============================================
# Teste rápido de instalação/verificação do PHP
# ============================================
echo "==================================================== APPLICATION ===================================================="
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y postfwd

# Descobre binário e config instalados pelo pacote
PFWBIN="$(command -v postfwd3 || command -v postfwd2 || command -v postfwd)"
PFWCFG="/etc/postfwd/postfwd.cf"; [ -f "$PFWCFG" ] || PFWCFG="/etc/postfwd.cf"

# (Opcional) se quiser usar o seu postfwd.cf, grave aqui em $PFWCFG
# cat > "$PFWCFG" <<'EOF'
# KingHost
id=limit-kinghost
pattern=recipient mx=.*kinghost.net
action=rate(global/300/3600) defer_if_permit "Limite de 300 e-mails por hora atingido para KingHost."

# UOL Host
id=limit-uolhost
pattern=recipient mx=.*uhserver
action=rate(global/300/3600) defer_if_permit "Limite de 300 e-mails por hora atingido para UOL Host."

# LocaWeb
id=limit-locaweb
pattern=recipient mx=.*locaweb.com.br
action=rate(global/500/3600) defer_if_permit "Limite de 500 e-mails por hora atingido para LocaWeb."

# Yahoo
id=limit-yahoo
pattern=recipient mx=.*yahoo.com
action=rate(global/150/3600) defer_if_permit "Limite de 150 e-mails por hora atingido para Yahoo."

# Mandic
id=limit-mandic
pattern=recipient mx=.*mandic.com.br
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Mandic."

# Titan
id=limit-titan
pattern=recipient mx=.*titan.email
action=rate(global/500/3600) defer_if_permit "Limite de 500 e-mails por hora atingido para Titan."

# Google
id=limit-google
pattern=recipient mx=.*google
action=rate(global/2000/3600) defer_if_permit "Limite de 2000 e-mails por hora atingido para Google."

# Hotmail
id=limit-hotmail
pattern=recipient mx=.*hotmail.com
action=rate(global/1000/86400) defer_if_permit "Limite de 1000 e-mails por dia atingido para Hotmail."

# Office 365
id=limit-office365
pattern=recipient mx=.*outlook.com
action=rate(global/2000/3600) defer_if_permit "Limite de 2000 e-mails por hora atingido para Office 365."

# Secureserver (GoDaddy)
id=limit-secureserver
pattern=recipient mx=.*secureserver.net
action=rate(global/300/3600) defer_if_permit "Limite de 300 e-mails por hora atingido para GoDaddy."

# Zimbra
id=limit-zimbra
pattern=recipient mx=.*zimbra
action=rate(global/400/3600) defer_if_permit "Limite de 400 e-mails por hora atingido para Zimbra."

# Argentina: Fibertel
id=limit-fibertel
pattern=recipient mx=.*fibertel.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Fibertel."

# Speedy
id=limit-speedy
pattern=recipient mx=.*speedy.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Speedy."

# Personal (Arnet)
id=limit-personal
pattern=recipient mx=.*personal.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Personal Arnet."

# Telecom
id=limit-telecom
pattern=recipient mx=.*telecom.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Telecom."

# Claro
id=limit-claro
pattern=recipient mx=.*claro.com.ar
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Claro."

# México: Telmex
id=limit-telmex
pattern=recipient mx=.*prodigy.net.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Telmex."

# Axtel
id=limit-axtel
pattern=recipient mx=.*axtel.net
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Axtel."

# Izzi
id=limit-izzi
pattern=recipient mx=.*izzi.net.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Izzi Telecom."

# Megacable
id=limit-megacable
pattern=recipient mx=.*megacable.com.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Megacable."

# TotalPlay
id=limit-totalplay
pattern=recipient mx=.*totalplay.net.mx
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para TotalPlay."

# Telcel
id=limit-telcel
pattern=recipient mx=.*telcel.net
action=rate(global/200/3600) defer_if_permit "Limite de 200 e-mails por hora atingido para Telcel."

# Outros (sem limite)
id=no-limit
pattern=recipient mx=.*
action=permit
# EOF
chmod 0644 "$PFWCFG"

# Override para garantir porta/interface/flags:
mkdir -p /etc/systemd/system/postfwd.service.d
cat > /etc/systemd/system/postfwd.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=$PFWBIN --nodaemon --shortlog --summary=600 --cache=600 --cache-rbl-timeout=3600 --cleanup-requests=1200 --cleanup-rbls=1800 --cleanup-rates=1200 --file=$PFWCFG --interface=127.0.0.1 --port=10045
EOF

systemctl daemon-reload
systemctl enable --now postfwd
systemctl restart postfix

# Healthcheck
systemctl status postfwd --no-pager
ss -ltnp | grep ':10045' || journalctl -u postfwd -n 80 --no-pager


read -p "Pressione ENTER para sair..."
