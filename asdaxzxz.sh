#!/bin/bash
# ============================================
# Teste rápido de instalação/verificação do PHP
# ============================================
echo "==================================================== APPLICATION ===================================================="
export DEBIAN_FRONTEND=noninteractive

# ---------- Instala Apache/PHP base e garante cURL (binário + extensão PHP) ----------
echo ">> Instalando Apache/PHP base..."
apt-get update -y
apt-get install -y apache2 php php-cli php-dev php-gd libapache2-mod-php php-mbstring curl

# Função utilitária: tenta instalar um pacote se ele existir no repo
try_install() {
  local pkg="$1"
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    apt-get install -y "$pkg"
    return 0
  fi
  return 1
}

echo ">> Garantindo extensão PHP cURL compatível..."
# 1) tenta meta-pacote genérico
if ! php -m | grep -qi '^curl$'; then
  try_install php-curl || true
fi

# 2) se ainda não carregou, tenta com a versão exata do PHP instalado
if ! php -m | grep -qi '^curl$'; then
  PHPV="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
  try_install "php${PHPV}-curl" || true
fi

# 3) ativa módulo e reinicia serviços
if command -v phpenmod >/dev/null 2>&1; then
  phpenmod curl || true
fi

if systemctl list-unit-files | grep -q '^apache2\.service'; then
  systemctl enable apache2 >/dev/null 2>&1 || true
  systemctl restart apache2 || true
fi

if systemctl list-units --type=service | grep -Eiq 'php[0-9\.]*-fpm\.service'; then
  systemctl restart "$(systemctl list-units --type=service | awk '/php[0-9\.]*-fpm\.service/ {print $1; exit}')" || true
fi

echo ">> Validando cURL no PHP..."
if php -m | grep -qi '^curl$' && php -r 'exit(function_exists("curl_init")?0:1);'; then
  echo "OK: extensão PHP cURL carregada."
else
  echo "❌ ERRO: a extensão PHP cURL não está carregada. Abortando para evitar falhas no shortener."
  exit 2
fi

read -p "Pressione ENTER para sair..."
