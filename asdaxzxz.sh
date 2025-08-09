#!/bin/bash
# ============================================
# Teste rápido de instalação/verificação do PHP
# ============================================
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if [ "$(id -u)" -ne 0 ]; then
  echo "❌ Este script precisa ser executado como root."
  exit 1
fi

echo ">> Verificando PHP..."
if command -v php >/dev/null 2>&1; then
    echo "✅ PHP já está instalado!"
    php -v | head -n 1
else
    echo "⚠️ PHP não encontrado. Tentando instalar..."
    apt-get update -y
    apt-get install -y php-cli php-common || {
        apt-get install -y php8.3-cli || \
        apt-get install -y php8.2-cli || \
        apt-get install -y php8.1-cli || \
        apt-get install -y php8.0-cli || \
        apt-get install -y php7.4-cli
    }

    # cria atalho se necessário
    if ! command -v php >/dev/null 2>&1; then
        PHP_BIN=$(command -v php8.3 || command -v php8.2 || command -v php8.1 || command -v php8.0 || command -v php7.4 || true)
        if [ -n "$PHP_BIN" ]; then
            ln -sf "$PHP_BIN" /usr/bin/php
            hash -r || true
        fi
    fi

    if command -v php >/dev/null 2>&1; then
        echo "✅ PHP instalado com sucesso!"
        php -v | head -n 1
    else
        echo "❌ Erro ao instalar o PHP!"
        exit 1
    fi
fi
