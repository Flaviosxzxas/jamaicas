#!/bin/bash

DOMAIN="$1"
SERVER_IP="$2"
CLOUDFLARE_API_KEY="$3"
CLOUDFLARE_EMAIL="$4"
OK=1

# Caminho do DKIM (RSPAMD)
DKIM_FILE="/opt/BillionMail/rspamd-data/dkim/$DOMAIN/default.pub"
DKIM_SELECTOR="default"

if [ -z "$DOMAIN" ] || [ -z "$SERVER_IP" ] || [ -z "$CLOUDFLARE_API_KEY" ] || [ -z "$CLOUDFLARE_EMAIL" ]; then
    echo "ERRO: Uso: $0 <DOMINIO> <IP> <CF_API_KEY> <CF_EMAIL>"
    exit 1
fi

if [ ! -f "$DKIM_FILE" ]; then
    echo "ERRO: Arquivo de DKIM não encontrado: $DKIM_FILE"
    exit 1
fi

# Extrai só a parte depois do p=, removendo espaços, parênteses, ; e lixo do final
PUBKEY=$(grep '^p=' "$DKIM_FILE" | sed 's/^p=//;s/[ \t\r\n]*//g' | tr -d '();')
if [ -z "$PUBKEY" ]; then
    PUBKEY=$(cat "$DKIM_FILE" | tr -d '\n\r\t"();' | sed -E 's/.*p=//;s/[ ]*//g')
fi
PUBKEY=$(echo "$PUBKEY" | sed 's/ *$//g')

if [ -z "$PUBKEY" ]; then
    echo "ERRO: Não foi possível extrair a chave pública do DKIM."
    exit 1
fi

DKIM_TXT_VALUE="v=DKIM1; k=rsa; p=$PUBKEY"
SPF_TXT_VALUE="v=spf1 +a +mx +ip4:$SERVER_IP -all"
DMARC_TXT_VALUE="v=DMARC1; p=quarantine; rua=mailto:admin@$DOMAIN"

if ! command -v jq &> /dev/null; then
    apt-get update -y >/dev/null 2>&1 && apt-get install -y jq >/dev/null 2>&1
fi
if ! command -v curl &> /dev/null; then
    apt-get update -y >/dev/null 2>&1 && apt-get install -y curl >/dev/null 2>&1
fi

cloudflare_dns_update() {
    local type="$1"
    local name="$2"
    local content="$3"
    local priority="$4"
    local zone_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN&status=active" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
        -H "Content-Type: application/json" | jq -r '.result[0].id')
    if [ -z "$zone_id" ] || [ "$zone_id" = "null" ]; then
        echo "ERRO: Não encontrou Zone ID Cloudflare para $DOMAIN"
        OK=0
        return 1
    fi

    local result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=$type&name=$name" \
        -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
        -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
        -H "Content-Type: application/json")
    local record_id=$(echo "$result" | jq -r '.result[0].id')

    local data
    if [ "$type" = "MX" ]; then
        data=$(jq -n --arg type "$type" --arg name "$name" --arg content "$content" --arg priority "$priority" --arg ttl "120" '{
            type: $type,
            name: $name,
            content: $content,
            priority: ($priority|tonumber),
            ttl: ($ttl|tonumber)
        }')
    else
        data=$(jq -n --arg type "$type" --arg name "$name" --arg content "$content" --arg ttl "120" '{
            type: $type,
            name: $name,
            content: $content,
            ttl: ($ttl|tonumber)
        }')
    fi

    local resp
    if [ -z "$record_id" ] || [ "$record_id" = "null" ]; then
        resp=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
            -H "Content-Type: application/json" \
            --data "$data")
    else
        resp=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
            -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
            -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
            -H "Content-Type: application/json" \
            --data "$data")
    fi

    local success=$(echo "$resp" | jq -r '.success')
    if [ "$success" != "true" ]; then
        echo "ERRO: Falha ao criar/atualizar $type $name."
        echo "RESPOSTA DO CLOUDFLARE:"
        echo "$resp"
        OK=0
    fi
}

cloudflare_dns_update "A" "$DOMAIN" "$SERVER_IP" ""
cloudflare_dns_update "A" "mail.$DOMAIN" "$SERVER_IP" ""
cloudflare_dns_update "MX" "$DOMAIN" "mail.$DOMAIN" "10"
cloudflare_dns_update "TXT" "$DOMAIN" "$SPF_TXT_VALUE" ""
cloudflare_dns_update "TXT" "$DKIM_SELECTOR._domainkey.$DOMAIN" "$DKIM_TXT_VALUE" ""
cloudflare_dns_update "TXT" "_dmarc.$DOMAIN" "$DMARC_TXT_VALUE" ""

# ============ CONFIGURAÇÃO SSL APACHE AUTOMÁTICA ============

# Instalar Apache e Certbot caso não existam
if ! command -v apache2 &> /dev/null; then
    apt-get update -y && apt-get install -y apache2
fi
if ! command -v certbot &> /dev/null; then
    apt-get install -y certbot python3-certbot-apache
fi

mkdir -p /var/www/html

a2enmod ssl
a2enmod rewrite

# PARA SERVIÇOS QUE USAM A PORTA 80
# PARA SERVIÇOS QUE USAM A PORTA 80
echo "Parando possíveis serviços que usam a porta 80 (nginx, apache, docker)..."
systemctl stop nginx 2>/dev/null
systemctl stop apache2 2>/dev/null
docker ps -q --filter "publish=80" | xargs -r docker stop

# Emite o certificado SSL Let's Encrypt (apenas se não existir)
if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    certbot certonly --standalone --agree-tos --register-unsafely-without-email -d "$DOMAIN" --non-interactive
fi

# Só depois que o certificado existir, crie o virtualhost:
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    cat <<EOF > "/etc/apache2/sites-available/ssl-$DOMAIN.conf"
<VirtualHost *:80>
    ServerName $DOMAIN
    DocumentRoot /opt/BillionMail/core/publi

    RewriteEngine On
    RewriteCond %{SERVER_NAME} =$DOMAIN
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName $DOMAIN
    DocumentRoot /var/www/html

    SSLEngine on

    SSLCertificateFile /etc/letsencrypt/live/$DOMAIN/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/$DOMAIN/privkey.pem
    #Include /etc/letsencrypt/options-ssl-apache.conf

    <Directory /opt/BillionMail/core/public>
       AllowOverride All
       Require all granted
    </Directory>
</VirtualHost>
</IfModule>
EOF

    systemctl start apache2
    a2ensite "ssl-$DOMAIN"
    systemctl reload apache2
    echo "Site HTTPS configurado e redirecionamento forçado para https://$DOMAIN/"
else
    echo "ERRO: Certificado SSL não foi emitido corretamente, verifique o log do certbot!"
fi

