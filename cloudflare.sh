# Criar registro SPF
if [ $(record_exists "$ServerName" "TXT") -eq 0 ]; then
  echo "  -- Cadastrando SPF"
  response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
       -H "X-Auth-Email: $CloudflareEmail" \
       -H "X-Auth-Key: $CloudflareAPI" \
       -H "Content-Type: application/json" \
       --data "$(jq -n --arg type "TXT" --arg name "$ServerName" --arg content "v=spf1 a:$ServerName ~all" --arg ttl "120" --argjson proxied false \
          '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber), proxied: $proxied}')")
  echo "Response (SPF): $response" >> /root/cloudflare_logs.txt
else
  echo "Registro SPF já existe. Pulando." >> /root/cloudflare_logs.txt
fi

# Criar registro DMARC
if [ $(record_exists "_dmarc.$ServerName" "TXT") -eq 0 ]; then
  echo "  -- Cadastrando DMARC"
  response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
       -H "X-Auth-Email: $CloudflareEmail" \
       -H "X-Auth-Key: $CloudflareAPI" \
       -H "Content-Type: application/json" \
       --data "$(jq -n --arg type "TXT" --arg name "_dmarc.$ServerName" --arg content "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc@$ServerName; rf=afrf; fo=0:1:d:s; ri=86000; adkim=r; aspf=r" --arg ttl "120" --argjson proxied false \
          '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber), proxied: $proxied}')")
  echo "Response (DMARC): $response" >> /root/cloudflare_logs.txt
else
  echo "Registro DMARC já existe. Pulando." >> /root/cloudflare_logs.txt
fi

# Criar registro DKIM
if [ $(record_exists "mail._domainkey.$ServerName" "TXT") -eq 0 ]; then
  echo "  -- Cadastrando DKIM"
  EscapedDKIMCode=$(printf '%s' "$DKIMCode" | sed 's/\"/\\\\\"/g')
  response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CloudflareZoneID/dns_records" \
       -H "X-Auth-Email: $CloudflareEmail" \
       -H "X-Auth-Key: $CloudflareAPI" \
       -H "Content-Type: application/json" \
       --data "$(jq -n --arg type "TXT" --arg name "mail._domainkey.$ServerName" --arg content "v=DKIM1; h=sha256; k=rsa; p=$EscapedDKIMCode" --arg ttl "120" --argjson proxied false \
          '{type: $type, name: $name, content: $content, ttl: ($ttl | tonumber), proxied: $proxied}')")
  echo "Response (DKIM): $response" >> /root/cloudflare_logs.txt
else
  echo "Registro DKIM já existe. Pulando." >> /root/cloudflare_logs.txt
fi

