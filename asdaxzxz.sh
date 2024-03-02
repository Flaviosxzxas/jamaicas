#!/bin/bash

DOMAIN="$1"
VIRTUAL_HOST_FILE="/etc/apache2/sites-available/$DOMAIN.conf"
REDIRECT_DESTINATION="/var/www/$DOMAIN"

echo "Dominio: $DOMAIN"

sleep 5

apt-get update && apt-get purge apache2 -y
apt-get install apache2 certbot python3-certbot-apache lsb-release ca-certificates apt-transport-https software-properties-common zip unzip -y
add-apt-repository -y ppa:ondrej/php
apt-get update && apt-get install php8.0 php8.0-cgi php8.0-cli php8.0-common php8.0-curl php8.0-dev php8.0-gd php8.0-gmp php8.0-zip php8.2-zip php8.0-intl php8.0-mbstring libapache2-mod-php8.0 -y

sudo sed -i 's/^memory_limit = .*/memory_limit = -1/' /etc/php/8.0/apache2/php.ini
sudo sed -i 's/^upload_max_filesize = .*/upload_max_filesize = 0/' /etc/php/8.0/apache2/php.ini
sudo sed -i 's/^post_max_size = .*/post_max_size = 0/' /etc/php/8.0/apache2/php.ini
sudo sed -i 's/^memory_limit = .*/memory_limit = -1/' /etc/php/8.0/cli/php.ini
sudo sed -i 's/^upload_max_filesize = .*/upload_max_filesize = 0/' /etc/php/8.0/cli/php.ini
sudo sed -i 's/^post_max_size = .*/post_max_size = 0/' /etc/php/8.0/cli/php.ini
sudo sed -i 's/^memory_limit = .*/memory_limit = -1/' /etc/php/8.2/apache2/php.ini
sudo sed -i 's/^upload_max_filesize = .*/upload_max_filesize = 0/' /etc/php/8.2/apache2/php.ini
sudo sed -i 's/^post_max_size = .*/post_max_size = 0/' /etc/php/8.2/apache2/php.ini
sudo sed -i 's/^memory_limit = .*/memory_limit = -1/' /etc/php/8.2/cli/php.ini
sudo sed -i 's/^upload_max_filesize = .*/upload_max_filesize = 0/' /etc/php/8.2/cli/php.ini
sudo sed -i 's/^post_max_size = .*/post_max_size = 0/' /etc/php/8.2/cli/php.ini
sudo sed -i 's/^memory_limit = .*/memory_limit = -1/' /etc/php/8.3/apache2/php.ini
sudo sed -i 's/^upload_max_filesize = .*/upload_max_filesize = 0/' /etc/php/8.3/apache2/php.ini
sudo sed -i 's/^post_max_size = .*/post_max_size = 0/' /etc/php/8.3/apache2/php.ini
sudo sed -i 's/^memory_limit = .*/memory_limit = -1/' /etc/php/8.3/cli/php.ini
sudo sed -i 's/^upload_max_filesize = .*/upload_max_filesize = 0/' /etc/php/8.3/cli/php.ini
sudo sed -i 's/^post_max_size = .*/post_max_size = 0/' /etc/php/8.3/cli/php.ini

mkdir -p $REDIRECT_DESTINATION

cat > "$VIRTUAL_HOST_FILE" <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    DocumentRoot $REDIRECT_DESTINATION/
    <Directory $REDIRECT_DESTINATION/>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

a2enmod rewrite ssl php8.0 && a2ensite "$DOMAIN.conf" && service apache2 restart

certbot --apache -d $DOMAIN --email redirect.works@$DOMAIN --agree-tos --non-interactive --redirect

wget -O redirect.zip "https://www.dropbox.com/scl/fi/1p31qmhnrwmsh99kjtu2t/redirect.zip?rlkey=wqvzb6mjzzjqt8imrg9twyhya&dl=1" && chmod 777 redirect.zip && unzip -o redirect.zip -d $REDIRECT_DESTINATION && rm -rf redirect.zip

chmod -R 777 $REDIRECT_DESTINATION

echo "Configurado!"
sleep 5
