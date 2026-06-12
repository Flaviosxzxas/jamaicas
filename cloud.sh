#!/bin/bash

set -Eeuo pipefail
trap 'echo "[ERRO] linha $LINENO: $BASH_COMMAND (status $?)" >&2' ERR

ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

# Extrair domínio raiz (ex: mail.exemplo.com → exemplo.com)
Domain=$(echo "$ServerName" | awk -F. '{print $(NF-1)"."$NF}')

# Obter IP público da VPS automaticamente
ServerIP=$(curl -s https://api.ipify.org)

# Nome do servidor de email
MailServerName="smtp.$Domain"
echo "================================================= Definir variáveis principais ================================================="


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

DKIMCode=$(/root/dkimcode.sh /var/lib/rspamd/dkim/$ServerName/default.pub)

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

# SPF limpo: esta VPS/IP é o único remetente autorizado
create_or_update_record "$ServerName" "TXT" "\"v=spf1 ip4:$ServerIP -all\"" ""

# DMARC - domínio novo + envio em massa: fase de monitoramento
create_or_update_record "_dmarc.$ServerName" "TXT" "\"v=DMARC1; p=none; sp=none; pct=100; rua=mailto:dmarc-reports@$ServerName; adkim=r; aspf=r; fo=1\"" ""

# DMARC - após alguns dias, se tudo estiver passando
# create_or_update_record "_dmarc.$ServerName" "TXT" "\"v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:dmarc-reports@$ServerName; adkim=r; aspf=r; fo=1\"" ""

# DMARC - domínio estável
# create_or_update_record "_dmarc.$ServerName" "TXT" "\"v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@$ServerName; adkim=r; aspf=r; fo=1\"" ""

# DKIM: precisa bater com o selector usado pelo Rspamd
create_or_update_record "default._domainkey.$ServerName" "TXT" "\"v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode\"" ""

# MX apontando para o host SMTP real
create_or_update_record "$ServerName" "MX" "$MailServerName" "10"
# ════════════════════════════════════════════════════════════
# MTA-STS + TLS-RPT (Gmail, Microsoft 365, Yahoo valorizam)
# ════════════════════════════════════════════════════════════

# ID único da policy — qualquer string. Convenção: data ou versão.
# Se mudar a policy depois, atualize esse ID para forçar revalidação.
MTASTS_POLICY_ID="$(date +%Y%m%d%H%M)"

# 1) A record do subdomínio que servirá a policy via HTTPS
create_or_update_record "mta-sts.$ServerName" "A" "$ServerIP" ""

# Subdomínios de suporte (unsubscribe one-click)
create_or_update_record "unsubscribe.$ServerName" "A" "$ServerIP" ""

# 2) TXT _mta-sts: avisa aos MTAs que existe uma policy
create_or_update_record "_mta-sts.$ServerName" "TXT" "\"v=STSv1; id=$MTASTS_POLICY_ID\"" ""

# 3) TXT _smtp._tls: TLS-RPT — para onde enviar relatórios de falha TLS
create_or_update_record "_smtp._tls.$ServerName" "TXT" "\"v=TLSRPTv1; rua=mailto:tls-reports@$ServerName\"" ""

echo "✓ Registros MTA-STS e TLS-RPT criados no Cloudflare"
echo "================================================= APPLICATION ================================================="
