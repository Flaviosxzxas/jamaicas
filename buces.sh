#!/bin/bash
if ! dpkg -l | grep -q postfix-policyd-spf-python; then
    echo "Pacote postfix-policyd-spf-python não encontrado. Instalando..."
    sudo apt update
    sudo apt install postfix-policyd-spf-python -y
else
    echo "Pacote postfix-policyd-spf-python já está instalado."
fi

# Adiciona regras do Policyd
echo "#######################################################

sudo systemctl restart postfix-policyd-spf
if [ $? -eq 0 ]; then
    echo "Serviço reiniciado com sucesso."
else
    echo "Falha ao reiniciar o serviço."
fi

# Aguarda interação do usuário para fechar o terminal
echo "Pressione Enter para sair..."
read
