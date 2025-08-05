#!/bin/bash

# Atualiza os repositórios e instala o PHP 8.1 CLI

# Desativa interação e erros verbosos para execução remota
export DEBIAN_FRONTEND=noninteractive

echo "🛠️ Instalando PHP 8.1 CLI..."

# Atualiza pacotes
apt update -y

# Instala php8.1-cli
apt install php8.1-cli -y

# Verifica se instalou corretamente
if command -v php >/dev/null 2>&1; then
    echo "✅ PHP instalado com sucesso! Versão: $(php -v | head -n 1)"
else
    echo "❌ Erro ao instalar o PHP!"
    exit 1
fi
