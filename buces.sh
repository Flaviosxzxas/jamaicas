#!/bin/bash
sudo systemctl restart postfix-policyd-spf
if [ $? -eq 0 ]; then
    echo "Serviço reiniciado com sucesso."
else
    echo "Falha ao reiniciar o serviço."
fi

# Aguarda interação do usuário para fechar o terminal
echo "Pressione Enter para sair..."
read
