#!/bin/bash
# ============================================
#  Hardening básico e root
# ============================================
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  exit 1
fi

# ============================================
#  Função: instalar PHP de forma robusta
# ============================================
ensure_php() {
  echo ">> Verificando PHP..."
  if command -v php >/dev/null 2>&1; then
    echo "OK: $(php -v | head -n 1)"
    return 0
  fi

  echo ">> PHP não encontrado. Tentando instalar..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y

    # 1) tenta meta-pacote padrão
    if apt-get install -y php-cli php-common; then
      :
    else
      echo "!! 'php-cli' não disponível no repo padrão."

      # 2) se for Ubuntu, habilita PPA do Ondřej
      if [ -f /etc/os-release ] && grep -qi ubuntu /etc/os-release; then
        echo ">> Adicionando PPA ppa:ondrej/php (Ubuntu)..."
        apt-get install -y software-properties-common ca-certificates
        add-apt-repository -y ppa:ondrej/php
        apt-get update -y
      fi

      # 3) tenta versões específicas em ordem
      apt-get install -y \
        php8.3-cli || apt-get install -y \
        php8.2-cli || apt-get install -y \
        php8.1-cli || apt-get install -y \
        php8.0-cli || apt-get install -y \
        php7.4-cli
    fi

    # Normaliza: garante /usr/bin/php
    if ! command -v php >/dev/null 2>&1; then
      PHP_CANDIDATO="$(command -v php8.3 || true)"
      PHP_CANDIDATO="${PHP_CANDIDATO:-$(command -v php8.2 || true)}"
      PHP_CANDIDATO="${PHP_CANDIDATO:-$(command -v php8.1 || true)}"
      PHP_CANDIDATO="${PHP_CANDIDATO:-$(command -v php8.0 || true)}"
      PHP_CANDIDATO="${PHP_CANDIDATO:-$(command -v php7.4 || true)}"
      PHP_CANDIDATO="${PHP_CANDIDATO:-$(command -v php7.3 || true)}"
      PHP_CANDIDATO="${PHP_CANDIDATO:-$(command -v php7.2 || true)}"
      PHP_CANDIDATO="${PHP_CANDIDATO:-$(command -v php5 || true)}"

      if [ -n "${PHP_CANDIDATO}" ]; then
        ln -sf "${PHP_CANDIDATO}" /usr/bin/php
        hash -r || true
      fi
    fi

    # Checagem final
    if ! command -v php >/dev/null 2>&1; then
      echo "ERRO: não foi possível disponibilizar o binário 'php'."
      exit 1
    fi

    echo "OK: $(php -v | head -n 1)"
  else
    echo "ERRO: gerenciador 'apt-get' não encontrado (esta função cobre Ubuntu/Debian)."
    exit 1
  fi
}

# ============================================
#  Chamada da função + upgrade seguro
# ============================================
ensure_php

# Verifica se instalou corretamente
if command -v php >/dev/null 2>&1; then
    echo "✅ PHP instalado com sucesso! Versão: $(php -v | head -n 1)"
else
    echo "❌ Erro ao instalar o PHP!"
    exit 1
fi
