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
# === FIM CLASSIFY-BOUNCES ===
