#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script completo de envio de e-mails com:
- Logging via logging module
- Uso de ThreadPoolExecutor
- Organização e modularização
- Atualização de título em tempo real dentro de worker_thread
- Verificação de conexão (s.noop()) antes de reutilizar SMTP
"""

import os
import sys
import time
import random
import threading
import requests
import smtplib
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# >>> NOVOS IMPORTS PARA REBOOT (Selenium) <<<
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service

# >>> IMPORTS PARA COLORAMA <<<
from colorama import Fore, Style, init
init(autoreset=True)

# >>> IMPORTS para BeautifulSoup e regex <<<
from bs4 import BeautifulSoup
import re

# >>> PARA FILA DE SMTP (round-robin) <<<
from collections import deque
import configparser

import email.utils
import email.mime.multipart
import email.mime.text

# >>> Módulo de Logging <<<
import logging

# Define a timeout padrão para todas as conexões de socket
socket.setdefaulttimeout(30)

########################################
# >>> EXCEÇÃO PERSONALIZADA PARA TRATAR O 5.7.1 <<<
########################################
class RetrySendMail(Exception):
    """
    Usada para indicar que detectamos "5.7.1 Message detected"
    e vamos reencurtar o link para tentar enviar novamente.
    """
    pass

# Lista de cores para [OK]
color_list = [
    Fore.GREEN, Fore.GREEN, Fore.GREEN,
    Fore.GREEN, Fore.GREEN, Fore.GREEN, Fore.GREEN
]

########################################
#    CONFIGURAÇÕES / GLOBAIS
########################################

lock_smtp = threading.Lock()
lock_emails = threading.Lock()
lock_counters = threading.Lock()
lock_link = threading.Lock()

smtp_deque = deque()  # [host, user, pass, port, ssl_bool, usage_count]
email_list = []
stop_all = False
sent_ok = 0
sent_fail = 0
sent_total = 0

# Para trocar link a cada 500 envios (ou 250 ajustado)
EMAILS_PER_LINK = 250
emails_since_last_link = 0
current_short_link = ""

zicadas_filename = "zicadas.log"
smtps_ok_filename = "SmtpsOK.txt"

# Para reiniciar modem a cada N e-mails *com sucesso* (ajuste conforme necessário)
next_reboot_threshold = 2500

# >>> NOVA FLAG PARA FORÇAR REBOOT AO DETECTAR RBL <<<
force_reboot_now = False

# >>> CONTADOR DE TENTATIVAS DE REBOOT POR CAUSA DE RBL <<<
rbl_reboot_count = 0
MAX_RBL_REBOOTS = 30  # máximo de trocas de IP

# Configs do config.ini
limit_per_smtp = None
pause_seconds = None
threads_number = None

# >>> Cache de conexões SMTP para reutilização <<<
smtp_connection_cache = {}  # chave: (host, user, pwd, port, use_ssl), valor: (obj smtp)

########################################
#  FUNÇÕES AUXILIARES DE LOGGING/MODULARIZAÇÃO
########################################
def setup_logging():
    """
    Configura o módulo logging (nível INFO e formato de data).
    """
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info("Logging configurado com sucesso.")

########################################
#    FUNÇÃO DE LOG PERSONALIZADA
########################################
def log_print(line:str, email:str=None):
    """
    - Se 'line' começar com "[OK]", significa envio bem-sucedido.
       -> Mostramos 'line' no console,
       -> e gravamos 'email' (se houver) em send.log.

    - Caso contrário (FAIL, INFO, DESCARTANDO, etc.):
       -> Gravamos em Failed.log e em sendfalhas.log,
       -> Não exibimos no console.
    """
    if line.startswith("[OK]"):
        clr = random.choice(color_list)  # cor para [OK]
        print(clr + line + Style.RESET_ALL)

        if email:
            with open("send.log", "a", encoding="utf-8") as sf:
                sf.write(email + "\n")
        else:
            with open("send.log", "a", encoding="utf-8") as sf:
                sf.write(line + "\n")
    else:
        with open("Failed.log", "a", encoding="utf-8") as ff:
            ff.write(line + "\n")
        with open("sendfalhas.log", "a", encoding="utf-8") as ff2:
            ff2.write(line + "\n")

########################################
#     FUNÇÕES DE UTILIDADE
########################################
def log_zicada(line:str):
    with open("zicadas.log", "a", encoding="utf-8", errors="ignore") as fz:
        fz.write(line.strip() + "\n")

def descartar_smtp(smtp_tuple, reason:str=""):
    """
    Remove SMTP do round-robin e registra no zicadas.
    """
    with lock_smtp:
        try:
            smtp_deque.remove(smtp_tuple)
        except ValueError:
            pass
    reason = reason if reason else "erro"
    line = f"[DESCARTANDO] {smtp_tuple} => DESCARTADO ({reason})"
    log_print(line)
    log_zicada(line)

def random_nums(length=6):
    return ''.join(random.choice('0123456789') for _ in range(length))

def random_alphanum(length=7):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(length))

def random_letters(length=8):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.choice(chars) for _ in range(length))

def random_alphanum1(length=7):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(length))

def shorten_url(long_url:str)->str:
    try:
        import urllib.parse
        encoded = urllib.parse.quote(long_url, safe="")
        api_url = f"https://is.gd/create.php?format=json&url={encoded}"
        r = requests.get(api_url, timeout=10)
        if r.ok:
            j = r.json()
            if 'shorturl' in j and j.get('errorcode', 0) == 0:
                return j['shorturl']
    except:
        pass
    return long_url

def load_smtp_list(filename:str):
    if not os.path.isfile(filename):
        print(f"ERRO: Arquivo '{filename}' não existe!")
        sys.exit(1)
    lines = []
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(";")
            if len(parts)<5:
                continue
            host = parts[0].strip()
            user = parts[1].strip()
            pwd  = parts[2].strip()
            port = int(parts[3].strip())
            ssl_str = parts[4].lower().strip()
            ssl_bool = (ssl_str == "true")
            lines.append([host, user, pwd, port, ssl_bool, 0])
    return lines

def load_email_list(filename:str):
    if not os.path.isfile(filename):
        print(f"ERRO: Arquivo de e-mails '{filename}' não existe!")
        sys.exit(1)
    lines = []
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line=line.strip()
            if line:
                lines.append(line)
    return lines

def load_name_list():
    fname = os.path.join("NegaMir", "Name.txt")
    if not os.path.isfile(fname):
        return []
    with open(fname, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip()]

def load_subject_list():
    fname = os.path.join("NegaMir", "Subject.txt")
    if not os.path.isfile(fname):
        return []
    with open(fname, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip()]

def load_letter():
    fname = os.path.join("NegaMir", "letter.txt")
    if not os.path.isfile(fname):
        return """<html><body>
<h2>Exemplo de corpo de e-mail</h2>
<p>Você pode editar <b>NegaMir/letter.txt</b> para personalizar.</p>
<p>Link: [-mylink-]</p>
<p>Nome: %name%</p>
</body></html>"""
    with open(fname, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def html_to_text_with_links(html: str) -> str:
    soup = BeautifulSoup(html, 'html.parser')
    for a in soup.find_all('a'):
        link_text = a.get_text()
        link_url = a.get('href', '')
        replacement = f"{link_text} ({link_url})"
        a.replace_with(replacement)
    text = soup.get_text(separator="\n")
    return text.strip()

def gerar_html_com_link_aleatorio():
    """
    Gera assunto, corpo de e-mail e nome aleatórios,
    substituindo marcadores e colocando o link encurtado no corpo.
    """
    s_list = load_subject_list()
    if s_list:
        subject = random.choice(s_list)
    else:
        subject = "Sem Assunto"

    r5  = random_nums(6)
    r6  = random_nums(6)
    r7  = random_alphanum(7)
    r8  = random_nums(8)
    r9  = random_letters(5)
    r10 = random_alphanum(4)
    r14 = random_alphanum1(7)

    subject = subject.replace("%random_New5%",  r5)
    subject = subject.replace("%random_New6%",  r6)
    subject = subject.replace("%random_New7%",  r7)
    subject = subject.replace("%random_New71%", r14)
    subject = subject.replace("%random_New8%",  r8)
    subject = subject.replace("%random_New9%",  r9)
    subject = subject.replace("%random_New10%", r10)

    letter_base = load_letter()
    n_list = load_name_list()
    chosen_name = random.choice(n_list) if n_list else "Teste"

    r6_body = random_nums(6)
    r7_body = random_alphanum(7)
    r8_body = random_letters(8)
    r9_body = random_alphanum(5)
    r10_body = random_nums(5)

    corpo = letter_base
    corpo = corpo.replace("%random_New6%", r6_body)
    corpo = corpo.replace("%random_New7%", r7_body)
    corpo = corpo.replace("%random_New8%", r8_body)
    corpo = corpo.replace("%name%", chosen_name)
    corpo = corpo.replace("%Name%", chosen_name)

    global current_short_link
    with lock_link:
        base_short = current_short_link

    link_final = base_short + f"?id=xx&id={r6_body}={r7_body}&uid={r8_body}&user={r9_body}&skin=skin{r10_body}"
    corpo = corpo.replace("[-mylink-]", link_final)

    return (subject, corpo, chosen_name)

def update_short_link():
    """
    Gera uma nova URL encurtada e salva na variável global current_short_link.
    """
    base_links = [
        "https://www.puertasycerrajeria.com",
        "https://www.ongonagency.com",
        "https://www.belezzavital.com",
    ]
    base = random.choice(base_links)
    rparam = random_alphanum(6)
    link_with_param = base + "?" + rparam
    shorted = shorten_url(link_with_param)
    global current_short_link
    with lock_link:
        current_short_link = shorted

########################################
# Nova implementação "exclusiva" do get_round_robin_smtp
# para evitar que várias threads peguem o mesmo SMTP simultaneamente.
########################################
def get_round_robin_smtp(limit_per_smtp, group_size):
    """
    Retira (popleft) SMTP do deque de forma segura e verifica se ele ainda
    pode enviar 'group_size' e-mails (usage_count + group_size <= limit_per_smtp).
    - Se sim, atualiza usage_count e retorna.
    - Se não, coloca-o de volta (append) e tenta o próximo.
    Retorna None se nenhum SMTP estiver disponível ou estiver acima do limite.
    """
    with lock_smtp:
        if not smtp_deque:
            return None
        found_smtp = None
        length = len(smtp_deque)
        for _ in range(length):
            st = smtp_deque.popleft()
            if (st[5] + group_size) <= limit_per_smtp:
                st[5] += group_size
                found_smtp = st
                break
            else:
                # Este SMTP está no limite ou acima, volta para o final e continua
                smtp_deque.append(st)
        return found_smtp

########################################
#  Reutilização de Conexão SMTP
########################################
def get_smtp_connection(smtp_tuple):
    """
    Retorna (obj_smtp) reutilizando se possível.
    Faz o login caso ainda não tenha sido feito ou se a conexão caiu.
    """
    (host, user, pwd, port, use_ssl, _) = smtp_tuple
    key = (host, user, pwd, port, use_ssl)

    with lock_smtp:
        cached = smtp_connection_cache.get(key)

    # Se não há cache ou a conexão está fechada, criar nova
    if not cached:
        try:
            if use_ssl:
                s = smtplib.SMTP_SSL(host, port, timeout=30)
            else:
                s = smtplib.SMTP(host, port, timeout=30)
            s.ehlo()
            if not use_ssl:
                try:
                    s.starttls()
                    s.ehlo()
                except:
                    pass
            s.login(user, pwd)
            with lock_smtp:
                smtp_connection_cache[key] = s
            return s
        except Exception as ex:
            raise ex
    else:
        # Tenta usar a conexão em cache
        s = cached
        try:
            s.noop()  # Testa se a conexão ainda está ativa
        except:
            # Se caiu, remover do cache e criar nova
            with lock_smtp:
                del smtp_connection_cache[key]

            if use_ssl:
                s = smtplib.SMTP_SSL(host, port, timeout=30)
            else:
                s = smtplib.SMTP(host, port, timeout=30)
            s.ehlo()
            if not use_ssl:
                try:
                    s.starttls()
                    s.ehlo()
                except:
                    pass
            s.login(user, pwd)

            with lock_smtp:
                smtp_connection_cache[key] = s
            return s
        return s

########################################
# do_send_mail_bcc (reutilizando conexões)
########################################
def do_send_mail_bcc(smtp_tuple, from_addr, group_recip, subject, html_body):
    """
    Agora usando a conexão do cache, se disponível.
    Faz sendmail e lida com exceções específicas.
    """
    r6 = random_nums(6)  # para exemplo de random em "To"

    host, user, pwd, port, use_ssl, usage_count = smtp_tuple
    to_main = group_recip[0]
    bcc_list = group_recip[1:] if len(group_recip) > 1 else []

    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["From"] = from_addr
    msg["To"] = f"{r6} <{to_main}>"
    msg["Subject"] = subject

    # Tentar extrair domínio do from_addr para o Message-ID
    tmp_email_for_domain = from_addr
    if "<" in from_addr and ">" in from_addr:
        try:
            tmp_email_for_domain = from_addr.split('<')[-1].split('>')[0]
        except:
            pass

    try:
        domain_part = tmp_email_for_domain.split('@')[1]
    except IndexError:
        domain_part = "fallback-domain.com"

    msg["Message-ID"] = email.utils.make_msgid(domain=domain_part)
    msg["Date"] = email.utils.formatdate(localtime=True)

    text_body = html_to_text_with_links(html_body)
    part_text = email.mime.text.MIMEText(text_body, "plain", "utf-8")
    msg.attach(part_text)
    part_html = email.mime.text.MIMEText(html_body, "html", "utf-8")
    msg.attach(part_html)

    try:
        s = get_smtp_connection(smtp_tuple)
        envelope = [to_main] + bcc_list
        s.sendmail(from_addr, envelope, msg.as_string())

    except smtplib.SMTPDataError as ex:
        txt = str(ex).lower()
        if "5.7.1 message detected" in txt:
            raise RetrySendMail("Detec 5.7.1 => reencurtar link e reenviar")
        raise ex

########################################
# >>> NOVA FUNÇÃO PARA VERIFICAR SE É ERRO QUE DEVE DESCARTAR SMTP <<<
########################################
def should_discard_error_message(error_message: str) -> bool:
    check = error_message.lower()
    patterns = [
        "421",
        "450",
        "452",
        "550",
        "554",
        "535",
        "policy violation",
        "service currently unavailable",
        "space shortage",
        "conta bloqueada por envio de spam",
        "sender address rejected",
        "delivery not allowed",
        "mailcount policy",
        "5.7.1",
        "has been suspended",
        "outgoing mail from",
        "mailbox is full",
        "verification failed for <",
        "too many invalid recipients",
        "currently blocked for sending",
        "outgoing mail suspension",
        "message discarded",
        "troque sua senha",
        "blocked for sending to too many invalid recipients",
    ]
    return any(p in check for p in patterns)

########################################
# >>> NOVA FUNÇÃO PARA DETECTAR BLOQUEIO POR RBL LOCAL (550) <<<
########################################
def is_rbl_block_error(error_message: str) -> bool:
    msg = error_message.lower()
    if "550" in msg and (
        "in an rbl" in msg or
        "bl.pro1.websitewelcome.com" in msg or
        "blocked - botnet detention" in msg
    ):
        return True
    return False

########################################
# >>> FUNÇÃO AUXILIAR PARA ATUALIZAR TÍTULO <<<
########################################
def update_console_title():
    """
    Atualiza o título da janela usando os contadores.
    Chamado tanto no loop principal quanto após cada envio no worker_thread.
    """
    with lock_counters:
        so = sent_ok
        sf = sent_fail
        total_env = so + sf
    with lock_smtp:
        active_smtps = len(smtp_deque)
    tot_smtps = len(smtp_deque)

    title_str = f"[SENDER] SMTPsRodando={active_smtps}/{tot_smtps} | Envios={total_env} Falhas={sf} Sucesso={so}"
    # Em Windows, podemos atualizar o título via os.system:
    os.system(f"title {title_str.replace('|', '^|')}")

########################################
# worker_thread (ThreadPoolExecutor)
########################################
def worker_thread(limit_per_smtp):
    """
    Esta função executa o envio de grupos de 5 e-mails, com retry (backoff exponencial).
    Também chama update_console_title() após cada lote.
    Cada thread sempre obtém (popleft) um SMTP único do deque (via get_round_robin_smtp),
    e no final do envio, se ainda estiver ok, devolve (append) pro deque.
    """
    global stop_all, sent_ok, sent_fail, sent_total, emails_since_last_link
    global force_reboot_now

    while not stop_all:
        group_recip = []
        with lock_emails:
            for _ in range(5):
                if email_list:
                    group_recip.append(email_list.pop())
                else:
                    break

        if not group_recip:
            break  # sem mais e-mails

        # Pegar SMTP exclusivo para estes 5 e-mails:
        st = get_round_robin_smtp(limit_per_smtp, len(group_recip))
        if not st:
            # Não há SMTP disponível ou todos atingiram limite
            # (Devolvemos os emails ao final da fila para tentar depois)
            with lock_emails:
                email_list.extend(group_recip)
            time.sleep(3)
            continue

        subject, corpo_html, chosen_name = gerar_html_com_link_aleatorio()
        from_addr = f'"{chosen_name}" <{st[1]}>'

        max_retries = 5
        attempt = 0
        wait_time = 1

        while attempt < max_retries:
            try:
                do_send_mail_bcc(st, from_addr, group_recip, subject, corpo_html)
                # Sucesso => contadores
                with lock_counters:
                    sent_ok += len(group_recip)
                    sent_total += len(group_recip)
                    emails_since_last_link += len(group_recip)

                for rcpt in group_recip:
                    log_print("[OK] ✉", rcpt)

                with lock_counters:
                    if emails_since_last_link >= EMAILS_PER_LINK:
                        update_short_link()
                        emails_since_last_link = 0

                # Antes de sair do loop de retry, atualiza título
                update_console_title()

                # Envio OK, podemos sair do loop de retry
                break

            except RetrySendMail:
                # Precisamos reencurtar o link e reenviar
                update_short_link()
                try:
                    do_send_mail_bcc(st, from_addr, group_recip, subject, corpo_html)
                    with lock_counters:
                        sent_ok += len(group_recip)
                        sent_total += len(group_recip)
                        emails_since_last_link += len(group_recip)

                    for rcpt in group_recip:
                        log_print("[OK] ✉", rcpt)

                    with lock_counters:
                        if emails_since_last_link >= EMAILS_PER_LINK:
                            update_short_link()
                            emails_since_last_link = 0

                    update_console_title()
                    break

                except Exception as ex2:
                    # Falhou mesmo após reencurtar
                    with lock_counters:
                        sent_fail += len(group_recip)
                        sent_total += len(group_recip)

                    discard_smtp = False
                    for rcpt in group_recip:
                        fail_line = f"[FAIL] {rcpt} via {st[0]};{st[1]} => {ex2}"
                        log_print(fail_line)
                        if (not discard_smtp) and should_discard_error_message(str(ex2)):
                            discard_smtp = True

                    if discard_smtp:
                        descartar_smtp(st, "Descartado por pattern de erro")

                    update_console_title()
                    # Neste caso, paramos o retry
                    break

            except Exception as ex:
                # Verificar se é RBL
                if is_rbl_block_error(str(ex)):
                    # => Botnet detention, etc. => REBOOT
                    with lock_emails:
                        email_list.extend(group_recip)

                    log_print("[RBL-FAIL] Erro 550 RBL detectado. Parando threads para reiniciar modem...")
                    force_reboot_now = True
                    stop_all = True

                    with lock_counters:
                        sent_fail += len(group_recip)
                        sent_total += len(group_recip)

                    for rcpt in group_recip:
                        fail_line = f"[FAIL] {rcpt} via {st[0]};{st[1]} => (RBL Detected) {ex}"
                        log_print(fail_line)

                    update_console_title()
                    # Importante: NÃO descartamos o SMTP (st) aqui!
                    # Precisamos mantê-lo para tentar após troca de IP
                    return  # Sai da worker_thread

                # Se não for RBL, é falha comum => retry com backoff
                attempt += 1
                if attempt >= max_retries:
                    with lock_counters:
                        sent_fail += len(group_recip)
                        sent_total += len(group_recip)

                    discard_smtp_flag = False
                    for rcpt in group_recip:
                        fail_line = f"[FAIL] {rcpt} via {st[0]};{st[1]} => {ex}"
                        log_print(fail_line)
                        if (not discard_smtp_flag) and should_discard_error_message(str(ex)):
                            discard_smtp_flag = True
                    if discard_smtp_flag:
                        descartar_smtp(st, "Descartado por pattern de erro")

                    update_console_title()

                else:
                    log_print(f"[INFO] Falha (tentativa {attempt}/{max_retries}) => {ex}")
                    time.sleep(wait_time)
                    wait_time *= 2

            # Fim do while de retry

        # Se chegamos aqui, ou deu certo antes do break, ou atingiu retries
        # Se foi sucesso, devolvemos o SMTP ao deque (se ainda dentro do limite)
        #   Obs: usage_count já está incrementado, mas se ultrapassar
        #   o limit_per_smtp, não voltamos.
        with lock_smtp:
            if st in smtp_deque:
                # Já foi descartado, não recolocamos
                pass
            else:
                # st[5] já incrementado.
                # Se usage_count não estourou, podemos recolocar.
                if st[5] < limit_per_smtp:
                    smtp_deque.append(st)

########################################
# Ler/criar config.ini
########################################
def load_config():
    cfg = configparser.ConfigParser()
    fname = "config.ini"
    if os.path.isfile(fname):
        cfg.read(fname)
        limit_str = cfg.get("SETTINGS", "limit", fallback="")
        pause_str = cfg.get("SETTINGS", "pause", fallback="")
        thr_str   = cfg.get("SETTINGS", "threads", fallback="")
        if not limit_str or not pause_str or not thr_str:
            limit_str, pause_str, thr_str = ask_and_write_config(cfg, fname)
        return limit_str, pause_str, thr_str
    else:
        cfg["SETTINGS"] = {}
        limit_str, pause_str, thr_str = ask_and_write_config(cfg, fname)
        return limit_str, pause_str, thr_str

def ask_and_write_config(cfg, fname):
    limit_str = input("[Pergunta] Qual limite por SMTP? ex:10 => ")
    if not limit_str.strip():
        limit_str = "10"
    pause_str = input("[Pergunta] Tempo de pausa (em horas) se TODAS no limite? => ")
    if not pause_str.strip():
        pause_str = "0.2"
    thr_str = input("[Pergunta] Threads? ex:2 => ")
    if not thr_str.strip():
        thr_str = "2"

    cfg["SETTINGS"]["limit"] = limit_str
    cfg["SETTINGS"]["pause"] = pause_str
    cfg["SETTINGS"]["threads"] = thr_str
    with open(fname, "w", encoding="utf-8") as f:
        cfg.write(f)
    return limit_str, pause_str, thr_str

########################################
# >>> FUNÇÕES/VARIÁVEIS AUXILIARES P/ O REBOOT <<<
########################################
la7mar = ""
labyadh = ""
lasfar = ""

def debug_log(msg):
    pass

def check_internet():
    try:
        subprocess.check_call(
            ["ping", "google.com", "-n", "1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except:
        return False

def get_public_ip():
    try:
        r = requests.get("https://api.ipify.org", timeout=10)
        if r.status_code == 200:
            return r.text.strip()
    except:
        pass
    return None

is_rebooting = False

def reboot_modem_and_wait():
    global is_rebooting
    debug_log("Entrando em reboot_modem_and_wait() (modem antigo + checagem de IP).")
    log_print("[RBL] Reiniciando modem para tentar trocar IP (Selenium)...")

    old_ip = get_public_ip()
    debug_log(f"IP atual (antes do reboot) => {old_ip}")

    chrome_driver_path = r"C:\selenium_drivers\chromedriver.exe"
    service = Service(chrome_driver_path)
    driver = webdriver.Chrome(service=service)

    try:
        driver.get("http://192.168.2.1/")
        time.sleep(2)

        driver.find_element(By.ID, "username").send_keys("admin")
        driver.find_element(By.ID, "password").send_keys("KjTxxl92@")

        driver.find_element(By.ID, "BTN_Login").click()
        time.sleep(3)

        driver.find_element(By.ID, "navi-system").click()
        time.sleep(2)

        reiniciar_link = driver.find_element(By.XPATH, "//a[.//font[@token='Reboot']]")
        reiniciar_link.click()
        time.sleep(2)

        ok_button = driver.find_element(By.XPATH, "//input[@name='OK' and @value='OK']")
        ok_button.click()
        time.sleep(5)

        log_print("[RBL] Modem está reiniciando...")

    except Exception as ex:
        debug_log(f"[REBOOT-SEL] Erro ao reiniciar modem: {ex}")
        log_print(f"[RBL] Erro ao reiniciar modem: {ex}")
    finally:
        driver.quit()

    log_print("[RBL] Aguardando 120s para modem voltar...")
    time.sleep(120)

    debug_log("Verificando conexão de internet após reboot do modem.")
    max_attempts = 30
    attempt = 0
    new_ip = None
    while attempt < max_attempts:
        if check_internet():
            new_ip = get_public_ip()
            debug_log(f"Conexão restabelecida (tentativa {attempt+1}/{max_attempts}). IP atual: {new_ip}")
            if new_ip and old_ip and new_ip != old_ip:
                print(lasfar + f"IP público mudou de {old_ip} para {new_ip}!" + labyadh)
                break
            else:
                print(la7mar + f"IP não mudou (continua {new_ip}). Tentando novamente em 10s..." + labyadh)
                time.sleep(10)
        else:
            print(la7mar + f"[RBL] Internet ainda não voltou (tentativa {attempt+1}/{max_attempts}). Aguardando 10s..." + labyadh)
            time.sleep(10)
        attempt += 1

    if not new_ip or (old_ip == new_ip):
        msg_erro = "[RBL] O IP não mudou após reiniciar o modem. Encerrando script."
        debug_log(msg_erro)
        print(la7mar + msg_erro + labyadh)
        sys.exit(1)

    debug_log("IP mudou; tentando novamente o envio após reboot.")
    print(la7mar + "[RBL] IP mudou. Tentando novamente o envio..." + labyadh)

def wait_for_internet():
    log_print("[RBL] Fazendo ping até a internet voltar...")
    while True:
        resp = os.system("ping -n 1 8.8.8.8 > nul 2>&1")
        if resp == 0:
            log_print("[RBL] Internet restabelecida!")
            break
        time.sleep(5)

########################################
# MAIN
########################################
def main():
    setup_logging()
    logging.info("=== Início da execução do script... ===")

    global stop_all, sent_ok, sent_fail, sent_total
    global next_reboot_threshold, smtp_deque
    global limit_per_smtp, pause_seconds, threads_number
    global force_reboot_now, rbl_reboot_count

    limit_str, pause_str, thr_str = load_config()
    limit_per_smtp = int(limit_str.strip())
    pause_hours = float(pause_str.strip())
    pause_seconds = int(pause_hours * 3600)
    threads_number = int(thr_str.strip())

    emailfile = input("[Pergunta] Arquivo de Emails => ")
    if not emailfile.strip():
        emailfile = "teste_email.txt"

    smtps = load_smtp_list("smtps.txt")
    for st in smtps:
        smtp_deque.append(st)

    global email_list
    email_list = load_email_list(emailfile)

    tot_smtps = len(smtp_deque)
    tot_emails = len(email_list)
    log_print(f"[INFO] Iniciando... smtps={tot_smtps} limit={limit_per_smtp} pause={pause_seconds}s threads={threads_number}, emails={tot_emails}")
    logging.info(f"Iniciando com {tot_smtps} SMTPs e {tot_emails} emails...")

    update_short_link()

    executor = ThreadPoolExecutor(max_workers=threads_number)
    for _ in range(threads_number):
        executor.submit(worker_thread, limit_per_smtp)

    # Loop principal de monitoramento
    while True:
        time.sleep(2)
        update_console_title()

        with lock_smtp:
            active_smtps = len(smtp_deque)
        with lock_counters:
            so = sent_ok
            sf = sent_fail
            total_env = so + sf

        title_str = f"[SENDER] SMTPsRodando={active_smtps}/{tot_smtps} | Envios={total_env} Falhas={sf} Sucesso={so}"
        log_print(f"[INFO] {title_str}")
        logging.info(title_str)

        # Se algum worker sinalizou RBL => force_reboot_now = True
        if force_reboot_now:
            # Vamos contar quantas vezes já reiniciamos
            rbl_reboot_count += 1
            if rbl_reboot_count > MAX_RBL_REBOOTS:
                log_print(f"[RBL] Erro 'botnet detention' persistiu após {MAX_RBL_REBOOTS} trocas de IP. Encerrando.")
                sys.exit(1)

            log_print("[REBOOT] RBL detectado. Reiniciando modem agora...")
            logging.warning("Forçando REBOOT agora (RBL detectado).")
            stop_all = True
            executor.shutdown(wait=True)

            log_print("[REBOOT] Reiniciando modem (aguarde)...")
            reboot_modem_and_wait()
            log_print("[REBOOT] Modem reiniciado. Checando internet...")

            wait_for_internet()
            log_print("[REBOOT] Internet voltou. Retomando envios...")
            force_reboot_now = False
            stop_all = False

            executor = ThreadPoolExecutor(max_workers=threads_number)
            for _ in range(threads_number):
                executor.submit(worker_thread, limit_per_smtp)

        with lock_counters:
            so_now = sent_ok

        # Reboot "programado" a cada 2500 envios (ajustável)
        if so_now >= next_reboot_threshold:
            log_print(f"[REBOOT] Atingiu ~{next_reboot_threshold} e-mails de sucesso. Reiniciando modem...")
            logging.warning("Reiniciando modem - threshold atingido.")
            stop_all = True
            executor.shutdown(wait=True)

            log_print("[REBOOT] Reiniciando modem (aguarde)...")
            reboot_modem_and_wait()
            next_reboot_threshold += 2500
            log_print("[REBOOT] Modem reiniciado. Checando internet...")

            wait_for_internet()
            log_print("[REBOOT] Internet voltou. Retomando envios...")
            stop_all = False
            executor = ThreadPoolExecutor(max_workers=threads_number)
            for _ in range(threads_number):
                executor.submit(worker_thread, limit_per_smtp)

        # Se acabaram os e-mails, encerramos
        with lock_emails:
            if not email_list:
                break

        # Se todos smtps atingiram limite, pausamos ou saímos
        with lock_smtp:
            cands = [s for s in smtp_deque if s[5] < limit_per_smtp]
        if not cands:
            if pause_seconds > 0:
                log_print(f"[INFO] Todos SMTPs no limite. Pausando {pause_seconds}s...")
                logging.info(f"Todos SMTPs no limite. Pausando {pause_seconds}s...")
                time.sleep(pause_seconds)
                with lock_smtp:
                    for s in smtp_deque:
                        s[5] = 0
            else:
                break

    stop_all = True
    executor.shutdown(wait=True)

    ans = input("Deseja salvar SMTPs boas (ainda na lista) em SmtpsOK.txt? (S/N) => ").strip().lower()
    if ans in ("s", "y"):
        with open(smtps_ok_filename, "w", encoding="utf-8") as f:
            with lock_smtp:
                for s in smtp_deque:
                    line = f"{s[0]};{s[1]};{s[2]};{s[3]};{str(s[4]).lower()}"
                    f.write(line + "\n")
        log_print(f"[INFO] Salvo {len(smtp_deque)} SMTPs boas em {smtps_ok_filename}.")

    print()
    log_print("[INFO] Final de TUDO. Stats:")
    with lock_counters:
        final_ok = sent_ok
        final_fail = sent_fail
        final_total = sent_total

    log_print(f"   Enviados com sucesso: {final_ok}")
    log_print(f"   Falhas: {final_fail}")
    log_print(f"   Total processado: {final_total}")

    logging.info("Final do script.")
    logging.info(f"Enviados com sucesso: {final_ok}, falhas: {final_fail}, total: {final_total}")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logging.exception("Erro não tratado durante a execução do script")
        sys.exit(1)
