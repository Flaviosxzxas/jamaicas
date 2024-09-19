#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

# Verifica se foi fornecido o argumento de domínio
if [ -z "$1" ]; then
    echo "Erro: Por favor, forneça o domínio como argumento."
    exit 1
fi

ServerName=$1
echo "==================================================== APPLICATION ===================================================="
sudo apt-get update
sudo apt-get dist-upgrade -y
sudo hostnamectl set-hostname "$ServerName"
sudo apt install -y toilet unzip curl
echo "$ServerName" | sudo tee /etc/hostname
echo "$ServerName" | sudo tee /proc/sys/kernel/hostname
sudo apt-get install -y software-properties-common
sudo add-apt-repository ppa:ondrej/php -y
sudo apt-get update -y
echo "postfix postfix/mailname string $ServerName" | sudo debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | sudo debconf-set-selections
sudo apt-get install -y nano apache2 php7.4 libapache2-mod-php7.4 php7.4-cli php7.4-mysql php7.4-gd php7.4-imagick php7.4-tidy php7.4-xmlrpc php7.4-common php7.4-xml php7.4-curl php7.4-dev php7.4-imap php7.4-mbstring php7.4-opcache php7.4-soap php7.4-zip php7.4-intl toilet unzip curl postfix --allow-unauthenticated --assume-yes
echo 'BlackRock /2024' | sudo toilet --filter metal > /etc/motd
sudo ufw disable
echo "==================================================== APPLICATION ===================================================="

echo "================================= Todos os comandos foram executados com sucesso! ==================================="

echo "======================================================= FIM =========================================================="

# Reiniciar servidor
echo "Reiniciando o servidor em 5 segundos..."
sleep 5
sudo reboot
