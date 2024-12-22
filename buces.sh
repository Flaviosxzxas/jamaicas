#!/bin/bash

# Verifique se o script está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi

# Definir variáveis principais
ServerName=$1
CloudflareAPI=$2
CloudflareEmail=$3

Domain=$(echo $ServerName | cut -d "." -f2-)
DKIMSelector=$(echo $ServerName | awk -F[.:] '{print $1}')
ServerIP=$(wget -qO- http://ip-api.com/line\?fields=query)

echo "Configurando Servidor: $ServerName"
echo "Domain: $Domain"
echo "DKIMSelector: $DKIMSelector"
echo "ServerIP: $ServerIP"

sleep 5

echo "Configurando postfix-policyd-spf-python"

# Criar o arquivo vazio com permissões apropriadas
sudo touch /etc/systemd/system/postfix-policyd-spf-python.service
sudo chmod 644 /etc/systemd/system/postfix-policyd-spf-python.service

# Preencher o arquivo com a configuração do serviço
sudo bash -c 'cat > /etc/systemd/system/postfix-policyd-spf-python.service <<EOF
[Unit]
Description=Postfix Policyd SPF Python
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/bin/policyd-spf
Type=simple
Restart=always
RestartSec=5
User=root
Group=root
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=postfix-policyd-spf-python

[Install]
WantedBy=multi-user.target
EOF'

# Remover o serviço postfix-policyd-spf-python (caso necessário)
echo "Removendo o serviço postfix-policyd-spf-python para evitar reinicializações desnecessárias..."
sudo systemctl stop postfix-policyd-spf-python
sudo systemctl disable postfix-policyd-spf-python
sudo systemctl daemon-reload

# Consolidar reinicializações ao final do script
echo "Recarregando e reiniciando os serviços..."
sudo systemctl daemon-reload
sudo systemctl enable postfix-policyd-spf-python
sudo systemctl restart postfix-policyd-spf-python
sudo systemctl restart postfix
