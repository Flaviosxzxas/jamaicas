#!/bin/bash
sudo systemctl restart postfix-policyd-spf
if [ $? -eq 0 ]; then
    echo "Serviço reiniciado com sucesso."
else
    echo "Falha ao reiniciar o serviço."
fi
