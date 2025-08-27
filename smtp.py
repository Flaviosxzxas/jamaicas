import string
import email.message as email
from time import gmtime, strftime
import sys
import ctypes
import threading
import time
from random import choice, randint
import smtplib
import os
import random
from colorama import init
from datetime import datetime
from multiprocessing.dummy import Pool as ThreadPool
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import ssl
import pdfkit
import PyPDF2
import tempfile
import socket
import subprocess
from bs4 import BeautifulSoup
import re
import socks
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
import requests  # <-- Para checar IP público

# Inicialização do colorama para cores no Windows
init()

# Ajusta o título do console (no Windows)
ctypes.windll.kernel32.SetConsoleTitleW('[Sender+Socks5+PDF + Reboot Modem RBL]')

# ---------------------------------------------------
# Configurações / Variáveis globais
# ---------------------------------------------------

WKHTMLTOPDF_PATH = r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"

count = 0        # não usado diretamente, mas mantido para consistência
countlive = 0    # conta envios bem-sucedidos
countdd = 0      # conta falhas
countall2 = 0    # conta total (falhas + sucessos)

limit_per_smtp = 0      # limite de envios por SMTP antes de pausar/remover
pause_seconds = 0       # tempo em segundos para pausar uma SMTP ao atingir o limite
delay_between_sends = 0.0

# Listas e dicionários de controle
SmtpListMem = []
usage_count = {}
paused_until = {}

smtp_lock = threading.RLock()

ProxyListMem = []
proxy_lock = threading.RLock()

proxy_fail_count = {}

round_robin_index = 0
proxy_round_index = 0

chunk_bcc_size = 1  # quantos destinatários por disparo em BCC

# Cores de terminal
la7mar  = '\x1b[91m'
lazra9  = '\x1b[94m'
la5dhar = '\x1b[92m'
movv    = '\x1b[95m'
lasfar  = '\x1b[93m'
ramadi  = '\x1b[90m'
blid    = '\x1b[1m'
star    = '\x1b[4m'
bigas   = '\x1b[07m'
bigbbs  = '\x1b[27m'
hell    = '\x1b[05m'
saker   = '\x1b[25m'
labyadh = '\x1b[00m'
cyan    = '\x1b[0;96m'

LOG_FILE = "debug.log"

# Usuário/senha do proxy Socks5 (caso necessário)
proxy_user = 'tiVI7BSEpGyx'
proxy_pass = 'tiVI7BSEpGyx'

data = ""
letter_path = 'NegaMir/letter.txt'
if not os.path.isfile(letter_path):
    print(la7mar + f'[ERRO] Arquivo {letter_path} não encontrado!' + labyadh)
    sys.exit(1)
else:
    with open(letter_path, 'r', encoding='utf-8', errors='ignore') as myfile:
        data = myfile.read() + '  '

pdf_enabled = False
pdf_html_content = ""

use_proxy = False

# Locks e flags para reboot
reboot_lock = threading.Lock()
is_rebooting = False
is_rebooting_lock = threading.Lock()


def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_logo():
    clear = '\x1b[0m'
    Year_Month_day = strftime('%Y-%m-%d', time.gmtime())
    x = f"""\n=== SENDER + SOCKS5 (Link c/ Sessão) + PDF + Reboot Modem RBL ===
        _____               [+] Multi-Thread + Round-Robin
    .-,;='';_),-.           [+] Proxy ou Local: Se RBL no Local => Reinicia Modem
     \\_\\(),()/_/            [+] Remove proxy se timed out / WinError 10060, etc.
       (,___,)              [+] Data   : {Year_Month_day}
      ,-/`~`\\-,___
     / /).:.('--._)
    {{_[ (_,_)              
        | Y |
       /  |  \\              
============================================================================================
"""
    color_rand = random.randint(31, 36)
    for line in x.split('\n'):
        sys.stdout.write(f'\x1b[1;{color_rand}m{line}{clear}\n')
        time.sleep(0.02)


def debug_log(message):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    thread_name = threading.current_thread().name
    full_msg = f"[{now}][{thread_name}] {message}\n"
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(full_msg)


def load_smtps():
    path = 'NegaMir/Smtps.txt'
    if not os.path.isfile(path):
        print(la7mar + f'[ERRO] Arquivo {path} não encontrado!' + labyadh)
        sys.exit(1)
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines


def parse_proxy_line(line):
    """Quebra a linha de proxy em (host, port)."""
    try:
        parts = line.split(':')
        if len(parts) < 2:
            print(la7mar + f"[ERRO] Linha de proxy inválida: {line}" + labyadh)
            return None
        host, port = parts[0], parts[1]
        return (host, port)
    except Exception as e:
        print(la7mar + f"[ERRO] Falha ao processar proxy: {e}" + labyadh)
        return None


def load_proxies():
    path = 'NegaMir/Proxies.txt'
    if not os.path.isfile(path):
        print(la7mar + f"[ERRO] Arquivo {path} não encontrado." + labyadh)
        sys.exit(1)

    proxies = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parsed = parse_proxy_line(line)
            if parsed is not None:
                proxies.append(parsed)

    if not proxies:
        print(la7mar + "[ERRO] Nenhum proxy válido encontrado." + labyadh)
        sys.exit(1)

    return proxies


def random_nums(length=6):
    return ''.join(random.choice('0123456789') for _ in range(length))


def random_alphanum(length=7):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(length))


def random_alphanum1(length=14):
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(length))


def random_letters(length=5):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.choice(chars) for _ in range(length))


def remove_smtp(smtp_line):
    """Remove a SMTP do pool e registra no log."""
    with smtp_lock:
        if smtp_line in SmtpListMem:
            SmtpListMem.remove(smtp_line)
        if smtp_line in paused_until:
            del paused_until[smtp_line]
        if smtp_line in usage_count:
            del usage_count[smtp_line]
    debug_log(f"SMTP REMOVIDA: {smtp_line}")


def pause_smtp(smtp_line, segundos):
    """Pausa (desabilita temporariamente) uma SMTP, reativando após X segundos."""
    with smtp_lock:
        paused_until[smtp_line] = time.time() + segundos
    debug_log(f"SMTP pausada por {segundos}s: {smtp_line}")


def get_active_smtp_count():
    now = time.time()
    active_count = 0
    with smtp_lock:
        for s in SmtpListMem:
            if s in paused_until and now < paused_until[s]:
                continue
            if usage_count.get(s, 0) >= limit_per_smtp:
                continue
            active_count += 1
    return active_count


def update_console_title():
    active_smtps = get_active_smtp_count()
    with smtp_lock:
        total_smtps = len(SmtpListMem)
    ctypes.windll.kernel32.SetConsoleTitleW(
        f'[Sender+Socks5+PDF+Reboot] '
        f'Ativas:{active_smtps}/{total_smtps} '
        f'Enviados:{countlive} Falhas:{countdd} '
        f'Total:{countall2}'
    )


def get_smtp_in_sequence():
    """
    Retorna a próxima SMTP em round-robin, respeitando:
      - SMTP pausada
      - SMTP que atingiu limit_per_smtp
    """
    global round_robin_index
    while True:
        with smtp_lock:
            if not SmtpListMem:
                debug_log("Nenhuma SMTP disponível. Retornando None.")
                return None

            tried = 0
            while tried < len(SmtpListMem):
                idx = round_robin_index % len(SmtpListMem)
                smtp_line = SmtpListMem[idx]
                now = time.time()

                # Verifica pausa ou uso excedido
                if (smtp_line in paused_until and now < paused_until[smtp_line]) or \
                   (usage_count.get(smtp_line, 0) >= limit_per_smtp):
                    round_robin_index += 1
                    tried += 1
                else:
                    chosen = smtp_line
                    round_robin_index += 1
                    return chosen

        # Se todas as SMTPs estavam pausadas ou no limite, espera e tenta resetar
        time.sleep(pause_seconds)
        with smtp_lock:
            for s2 in SmtpListMem:
                usage_count[s2] = 0
                paused_until[s2] = 0
            round_robin_index = 0


def remove_proxy(proxy_tuple):
    """Remove um proxy do pool e registra no log."""
    with proxy_lock:
        if proxy_tuple in ProxyListMem:
            ProxyListMem.remove(proxy_tuple)
        if proxy_tuple in proxy_fail_count:
            del proxy_fail_count[proxy_tuple]
    debug_log(f"PROXY REMOVIDA: {proxy_tuple}")


def get_proxy_in_sequence():
    global proxy_round_index
    with proxy_lock:
        if not ProxyListMem:
            print(la7mar + "[ERRO] Nenhum proxy disponível." + labyadh)
            return None

        index = proxy_round_index % len(ProxyListMem)
        proxy_tuple = ProxyListMem[index]
        proxy_round_index += 1
        return proxy_tuple


def connect_smtp_with_proxy(serveraddr, serverport, ssl_used, proxy_tuple, timeout=60):
    """
    Conecta ao servidor SMTP usando SOCKS5, envolve em SSL se necessário.
    """
    p_host, p_port = proxy_tuple
    sock = socks.socksocket()
    sock.settimeout(timeout)
    resolved_ip = socket.gethostbyname(serveraddr)  # resolve DNS

    sock.setproxy(
        proxy_type = socks.PROXY_TYPE_SOCKS5,
        addr       = p_host,
        port       = int(p_port),
        rdns       = False,
        username   = proxy_user,
        password   = proxy_pass
    )
    sock.connect((resolved_ip, serverport))

    if ssl_used == 'true':
        context = ssl.create_default_context()
        ssl_sock = context.wrap_socket(sock, server_hostname=serveraddr)
        ssl_sock.settimeout(timeout)

        server = smtplib.SMTP_SSL(host=None, port=None)
        server.sock = ssl_sock
        server.file = server.sock.makefile('rb')
        server._host = serveraddr
        server._port = serverport
        server.connect(serveraddr, serverport)
        server.ehlo()
    else:
        server = smtplib.SMTP(host=None, port=None)
        server.sock = sock
        server.file = server.sock.makefile('rb')
        server._host = serveraddr
        server._port = serverport
        server.connect(serveraddr, serverport)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.sock.settimeout(timeout)

    return server


def connect_smtp_local(serveraddr, serverport, ssl_used, timeout=60):
    """Conecta ao servidor SMTP sem proxy (direto)."""
    if ssl_used == 'true':
        server = smtplib.SMTP_SSL(serveraddr, serverport, timeout=timeout)
        server.ehlo()
    else:
        server = smtplib.SMTP(serveraddr, serverport, timeout=timeout)
        server.ehlo()
        server.starttls()
        server.ehlo()
    return server


def random_senha_numerica():
    length = random.randint(3, 6)
    return ''.join(random.choice('0123456789') for _ in range(length))


def ler_nameanexo_e_substituir_variaveis():
    """
    Lê o arquivo NameAnexo.txt e substitui variáveis (%random_NewX% etc.).
    Retorna o nome do PDF resultante.
    """
    path_name = 'NegaMir/NameAnexo.txt'
    if not os.path.isfile(path_name):
        return "Anexo.pdf"
    with open(path_name, 'r', encoding='utf-8', errors='ignore') as f:
        template = f.read().strip()

    template = template.replace('%random_New5%',  random_nums(5))
    template = template.replace('%random_New6%',  random_nums(6))
    template = template.replace('%random_New7%',  random_alphanum(7))
    template = template.replace('%random_New77%', random_alphanum1(7))
    template = template.replace('%random_New8%',  random_nums(8))
    template = template.replace('%random_New9%',  random_letters(5))
    template = template.replace('%random_New10%', random_alphanum(4))

    if not template.lower().endswith('.pdf'):
        template += '.pdf'
    return template


def unique_temp_names():
    import threading
    rnd = random_alphanum(6)
    tname = threading.current_thread().name
    temp_html  = os.path.join(tempfile.gettempdir(), f"temp_pdfdoc_{tname}_{rnd}.html")
    temp_pdf   = os.path.join(tempfile.gettempdir(), f"temp_pdf_{tname}_{rnd}.pdf")
    temp_pdfenc= os.path.join(tempfile.gettempdir(), f"temp_pdf_enc_{tname}_{rnd}.pdf")
    return temp_html, temp_pdf, temp_pdfenc


def gerar_pdf_criptografado(html_content, pdf_password):
    """
    Gera o PDF a partir do HTML (via pdfkit) e depois criptografa via PyPDF2.
    """
    num_inputs = random.randint(5, 20)
    hidden_inputs = ""
    for _ in range(num_inputs):
        random_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        hidden_inputs += f'<input type="hidden" id="{random_id}" value="dummy">\n'

    if '<body>' in html_content.lower():
        html_content = html_content.replace('<body>', f'<body>\n{hidden_inputs}', 1)
    else:
        html_content = hidden_inputs + html_content

    temp_html, temp_pdf, temp_pdf_enc = unique_temp_names()
    config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)

    try:
        with open(temp_html, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(html_content)

        pdfkit.from_file(temp_html, temp_pdf, configuration=config, options={'quiet': ''})

        reader = PyPDF2.PdfReader(temp_pdf)
        writer = PyPDF2.PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        # Criptografia
        writer.encrypt(user_password=pdf_password, owner_password=None, use_128bit=True)

        with open(temp_pdf_enc, 'wb') as f:
            writer.write(f)

        with open(temp_pdf_enc, 'rb') as f:
            pdf_bytes = f.read()

        return pdf_bytes
    except Exception as e:
        print(la7mar + f"[ERRO] Falhou ao gerar PDF: {e}" + labyadh)
        return None
    finally:
        for fn in [temp_html, temp_pdf, temp_pdf_enc]:
            if os.path.exists(fn):
                try:
                    os.remove(fn)
                except:
                    pass


def html_to_text_with_links(html: str) -> str:
    """
    Converte HTML em texto “simples”, adicionando link (URL) após o texto <a>.
    """
    soup = BeautifulSoup(html, 'html.parser')
    for a in soup.find_all('a'):
        link_text = a.get_text()
        link_url = a.get('href', '')
        replacement = f"{link_text} ({link_url})"
        a.replace_with(replacement)
    text = soup.get_text()
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def check_internet():
    """Verifica se há conectividade com a internet pingando google.com."""
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
    """
    Tenta obter o IP público consultando um serviço externo.
    """
    try:
        resp = requests.get("https://api.ipify.org", timeout=10)
        if resp.status_code == 200:
            return resp.text.strip()
    except:
        pass
    return None


def reboot_modem_and_wait():
    global is_rebooting  # <--- colocar no início da função

    debug_log("Entrando em reboot_modem_and_wait() (modem antigo + checagem de IP).")
    print(la7mar + "[RBL] Reiniciando modem para tentar trocar IP (Selenium)..." + labyadh)

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

        print(la7mar + "[RBL] Modem está reiniciando..." + labyadh)

    except Exception as ex:
        debug_log(f"[REBOOT-SEL] Erro ao reiniciar modem: {ex}")
        print(la7mar + f"[RBL] Erro ao reiniciar modem: {ex}" + labyadh)
    finally:
        driver.quit()

    print(la7mar + "[RBL] Aguardando 120s para modem voltar..." + labyadh)
    time.sleep(120)

    debug_log("Verificando conexão de internet após reboot do modem.")
    max_attempts = 10
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


def send_single_email(recipients, is_sms=False):
    global is_rebooting  # <--- colocar no início da função
    global countall2, countlive, countdd, pdf_enabled, pdf_html_content, use_proxy

    if not recipients:
        return

    max_attempts = 5
    emails_sent = False

    # >>> Se outra thread estiver rebootando, aguarda antes de começar
    while True:
        with is_rebooting_lock:
            if not is_rebooting:
                break
        time.sleep(3)

    for attempt in range(max_attempts):
        smtp_line = get_smtp_in_sequence()
        if not smtp_line:
            fail_count = len(recipients)
            countdd += fail_count
            countall2 += fail_count
            update_console_title()
            with open('Failed.log', 'a', encoding='utf-8') as fail_file:
                for rc in recipients:
                    fail_file.write(f'{rc} | Falha-SEM_SMTP\n')
            return

        try:
            ch = smtp_line.split(';')
            serveraddr = ch[0]
            fromaddr   = ch[1]
            SMTP_PASS  = ch[2]
            serverport = int(ch[3])
            ssl_used   = ch[4].lower()

            with open('NegaMir/Name.txt', 'r', encoding='utf-8') as nx:
                names = nx.read().splitlines()
                Name = random.choice(names) if names else "Teste"

            with open('NegaMir/Subject.txt', 'r', encoding='utf-8') as sx:
                subs = sx.read().splitlines()
                Subject = random.choice(subs) if subs else "Sem Assunto"

            r5  = random_nums(6)
            r6  = random_nums(6)
            r7  = random_alphanum(7)
            r8  = random_nums(8)
            r9  = random_letters(5)
            r10 = random_alphanum(4)
            r14 = random_alphanum1(7)

            Subject = Subject.replace("%random_New5%",  r5)
            Subject = Subject.replace("%random_New6%",  r6)
            Subject = Subject.replace("%random_New7%",  r7)
            Subject = Subject.replace("%random_New71%", r14)
            Subject = Subject.replace("%random_New8%",  r8)
            Subject = Subject.replace("%random_New9%",  r9)
            Subject = Subject.replace("%random_New10%", r10)

            local_data = data
            link_str = f"?id=xx&id={r6}={r7}&uid={r8}&user={r9}&skin=skin{r10}"

            local_data = local_data.replace("%random_New5%",  r5)
            local_data = local_data.replace("%random_New6%",  r6)
            local_data = local_data.replace("%random_New7%",  r7)
            local_data = local_data.replace("%random_New8%",  r8)
            local_data = local_data.replace("%random_New9%",  r9)
            local_data = local_data.replace("%random_New10%", r10)
            local_data = local_data.replace("[-mylink-]",     link_str)
            local_data = local_data.replace("%fromaddr%",     fromaddr)

            pdf_bytes = None
            pdf_name  = None
            if pdf_enabled and pdf_html_content:
                pdf_password = random_senha_numerica()
                local_data = local_data.replace("[SENHA]", pdf_password)
                local_pdf_html = pdf_html_content.replace("[SENHA]", pdf_password)
                local_pdf_html = local_pdf_html.replace("[-mylink-]", link_str)
                local_pdf_html = local_pdf_html.replace("%random_New5%",  r5)
                local_pdf_html = local_pdf_html.replace("%random_New6%",  r6)
                local_pdf_html = local_pdf_html.replace("%random_New7%",  r7)
                local_pdf_html = local_pdf_html.replace("%random_New8%",  r8)
                local_pdf_html = local_pdf_html.replace("%random_New9%",  r9)
                local_pdf_html = local_pdf_html.replace("%random_New10%", r10)

                pdf_bytes = gerar_pdf_criptografado(local_pdf_html, pdf_password)
                pdf_name  = ler_nameanexo_e_substituir_variaveis()
            else:
                local_data = local_data.replace("[SENHA]", "")

            text_content = html_to_text_with_links(local_data)

            msg = MIMEMultipart('alternative')
            msg['Subject'] = Subject
            if is_sms:
                msg['From'] = Name
            else:
                msg['From'] = f'{Name} <{fromaddr}>'
            msg['To'] = f"{r6} <{recipients[0]}>"

            bcc_list = recipients[1:] if len(recipients) > 1 else []

            removal_link = f"https://www.google.com/#{r5}.rem.php?email={recipients[0]}"
            msg.add_header("List-Remove", f"<{removal_link}>, <mailto:{recipients[0]}?subject=remove>")

            domain_from = fromaddr.split('@')[-1] if '@' in fromaddr else 'example.com'
            msg['Date'] = email.utils.formatdate(localtime=True)
            msg['Message-ID'] = email.utils.make_msgid(domain=domain_from)

            msg.attach(MIMEText(text_content, 'plain', 'utf-8'))
            msg.attach(MIMEText(local_data,  'html',  'utf-8'))

            if pdf_enabled and pdf_bytes:
                part = MIMEBase('application', 'pdf')
                part.set_payload(pdf_bytes)
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={pdf_name}')
                part.add_header('Content-Type', f'application/pdf; name="{pdf_name}"')
                msg.attach(part)

            if use_proxy:
                proxy_tuple = get_proxy_in_sequence()
                if not proxy_tuple:
                    fail_count = len(recipients)
                    countdd += fail_count
                    countall2 += fail_count
                    update_console_title()
                    with open('Failed.log', 'a', encoding='utf-8') as fail_file:
                        for rc in recipients:
                            fail_file.write(f'{rc} | Falha-SEM_PROXY\n')
                    return
                server = connect_smtp_with_proxy(serveraddr, serverport, ssl_used, proxy_tuple, timeout=60)
            else:
                server = connect_smtp_local(serveraddr, serverport, ssl_used, timeout=60)

            server.login(fromaddr, SMTP_PASS)
            server.sendmail(fromaddr, [recipients[0]] + bcc_list, msg.as_string())
            server.quit()

            now = datetime.now().strftime('%H:%M:%S')
            print(la5dhar + '--------------------------------------作品發送者---------------------------------------' + labyadh)
            print(lasfar + f'Time       : {la7mar}{now}{labyadh}')
            print(lasfar + f'To         : {la7mar}{recipients[0]}{labyadh}')
            print(lasfar + f'Subject    : {la7mar}{Subject}{labyadh}')
            print(lasfar + f'Name       : {la7mar}{Name}{labyadh}')
            print(lasfar + f'Smtp       : {la7mar}{serveraddr}{labyadh}')
            if use_proxy:
                print(lasfar + f'Proxy      : {la7mar}{proxy_tuple}{labyadh}')
            print(lasfar + 'Status     :' + la5dhar + ' Success' + labyadh)
            print(la5dhar + '-----------------------------------------------------------------------------------' + labyadh)

            with smtp_lock:
                usage_count[smtp_line] = usage_count.get(smtp_line, 0) + 1
                if usage_count[smtp_line] >= limit_per_smtp:
                    pause_smtp(smtp_line, pause_seconds)

            chunk_len = len(recipients)
            countall2 += chunk_len
            countlive += chunk_len

            with open('Sent.log', 'a', encoding='utf-8') as success_file:
                for rc in recipients:
                    success_file.write(rc + '\n')

            update_console_title()
            emails_sent = True
            break  # sai do loop de tentativas

        except Exception as e:
            err_str = str(e).lower()
            debug_log(f"Falha no envio => {e}")

            # Se for erro de conexão e estamos rebootando, retentar
            conexao_caiu = False
            if ("timed out" in err_str or
                "no route to host" in err_str or
                "10060" in err_str or
                "connection refused" in err_str):
                conexao_caiu = True

            if conexao_caiu:
                with is_rebooting_lock:
                    if is_rebooting:
                        print(la7mar + "Conexão falhou, mas modem está em reboot. Aguardando e tentando novamente..." + labyadh)
                        time.sleep(10)
                        continue

            if "10053" in err_str:
                print(la7mar + f"[ERRO] WinError 10053 => Conexão anulada pelo host local. Removendo SMTP." + labyadh)
                remove_smtp(smtp_line)
                fail_count = len(recipients)
                countdd += fail_count
                countall2 += fail_count
                update_console_title()
                with open('Failed.log', 'a', encoding='utf-8') as fail_file:
                    for rc in recipients:
                        fail_file.write(f'{rc} | Falha-WinError10053\n')
                return

            if "535" in err_str:
                print(la7mar + f"[AUTH-ERROR 535] Credenciais inválidas => removendo SMTP. (Tentativa {attempt+1}/{max_attempts})" + labyadh)
                remove_smtp(smtp_line)
                with open("dead.txt", "a", encoding="utf-8") as fblocked:
                    fblocked.write(f"{smtp_line} | {str(e)}\n")
                continue

            if "452" in err_str or "incorrect authentication data" in err_str:
                print(la7mar + f"Erro 452 / Auth => Removendo SMTP. (Tentativa {attempt+1}/{max_attempts})" + labyadh)
                remove_smtp(smtp_line)
                continue

            if ("550" in err_str) and ("bl.pro1.websitewelcome.com" in err_str):
                # RBL local
                if use_proxy:
                    print(la7mar + f'[RBL/Blocked c/ Proxy] Removendo SMTP: {smtp_line} => Erro: {str(e)}' + labyadh)
                    debug_log(f"RBL c/ proxy => Remove SMTP => {smtp_line}")
                    remove_smtp(smtp_line)
                else:
                    debug_log(f"[RBL-LOCAL] IP na RBL => Tentar reiniciar modem. Erro: {str(e)}")
                    with reboot_lock:
                        if not is_rebooting:
                            with is_rebooting_lock:
                                is_rebooting = True
                            os.system("ipconfig /flushdns")
                            reboot_modem_and_wait()

                            tentativas = 0
                            max_tent = 20
                            while tentativas < max_tent:
                                if check_internet():
                                    break
                                time.sleep(5)
                                tentativas += 1
                            with is_rebooting_lock:
                                is_rebooting = False
                continue

            # 550 normal
            if "550" in err_str:
                blocked_substrings = [
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
                if any(sb in err_str for sb in blocked_substrings):
                    print(la7mar + f'[BLOQUEIO 550] A conta/SMTP foi bloqueada. Erro: {str(e)}' + labyadh)
                    debug_log(f"Detectado 550 blocked => {smtp_line}")
                    remove_smtp(smtp_line)
                    with open("blockedSmtps.txt", "a", encoding="utf-8") as fblocked:
                        fblocked.write(f"{smtp_line} | {str(e)}\n")

                    fail_count = len(recipients)
                    countdd += fail_count
                    countall2 += fail_count
                    update_console_title()
                    with open('Failed.log', 'a', encoding='utf-8') as fail_file:
                        for rc in recipients:
                            fail_file.write(f'{rc} | Falha-550\n')
                    return

            # Outros erros => remove SMTP e falha para o chunk
            remove_smtp(smtp_line)
            fail_count = len(recipients)
            countdd += fail_count
            countall2 += fail_count
            update_console_title()
            with open('Failed.log', 'a', encoding='utf-8') as fail_file:
                for rc in recipients:
                    fail_file.write(f'{rc} | Falha-genérica: {str(e)}\n')
            return

        if delay_between_sends > 0:
            time.sleep(delay_between_sends)

    if not emails_sent:
        fail_count = len(recipients)
        countdd += fail_count
        countall2 += fail_count
        update_console_title()
        with open('Failed.log', 'a', encoding='utf-8') as fail_file:
            for rc in recipients:
                fail_file.write(f'{rc} | Falha-excedeu-tentativas\n')


def chunkify(lst, chunk_size):
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i+chunk_size]


def ProcessEmailsChunk(recipients_chunk):
    send_single_email(recipients_chunk, is_sms=False)


def ProcessSMSChunk(recipients_chunk):
    send_single_email(recipients_chunk, is_sms=True)


def SaveValidSmtps():
    now = datetime.now().strftime('%Y_%m_%d-%H%M%S')
    filename = f"ValidSmtps-{now}.txt"
    debug_log(f"Salvando SMTPS válidas em {filename}")
    with smtp_lock:
        if len(SmtpListMem) == 0:
            print(la7mar + "Não há SMTPS válidas para salvar." + labyadh)
            return
        with open(filename, 'w', encoding='utf-8') as f:
            for line in SmtpListMem:
                f.write(line + '\n')
    print(la5dhar + f"Smtps válidas salvas em: {filename}" + labyadh)


def SaveValidProxies():
    now = datetime.now().strftime('%Y_%m_%d-%H%M%S')
    filename = f"ValidProxies-{now}.txt"
    debug_log(f"Salvando Proxies válidas em {filename}")
    with proxy_lock:
        if len(ProxyListMem) == 0:
            print(la7mar + "Não há Proxies válidas para salvar." + labyadh)
            return
        with open(filename, 'w', encoding='utf-8') as f:
            for (host, port) in ProxyListMem:
                f.write(f"{host}:{port}\n")
    print(la5dhar + f"Proxies válidas salvas em: {filename}" + labyadh)


def ShowReport():
    print()
    print("="*80)
    print(f"Envio finalizado!\n\n  Total Processado: {countall2}\n  Enviados com Sucesso: {countlive}\n  Falhas: {countdd}")
    print("="*80)
    print()
    resp_save = input("Deseja salvar as SMTPS válidas? [S/N]: ").strip().lower()
    if resp_save.startswith('s'):
        SaveValidSmtps()
    
    if use_proxy:
        resp_savep = input("Deseja salvar as Proxies válidas? [S/N]: ").strip().lower()
        if resp_savep.startswith('s'):
            SaveValidProxies()

    resp = input("Deseja voltar ao menu inicial? [S/N]: ").strip().lower()
    if resp.startswith('s'):
        Choose()
    else:
        print("Encerrando o programa...")
        sys.exit(0)


def Choose():
    """
    Menu principal para configurar e iniciar o envio (Emails ou SMS),
    definindo chunks, limites, pausas e se usará Proxy ou não.
    """
    global count, countlive, countdd, countall2
    global limit_per_smtp, pause_seconds, delay_between_sends, chunk_bcc_size
    global pdf_enabled, pdf_html_content, data
    global use_proxy

    # Zera contadores
    count = 0
    countlive = 0
    countdd = 0
    countall2 = 0

    cls()
    print_logo()

    resp_pdf = input("Deseja gerar/anexar PDF c/ senha? (S/N): ").strip().lower()
    if resp_pdf.startswith('s'):
        pdf_enabled = True
        pdfdoc_path = 'NegaMir/PdfDoc.html'
        if os.path.isfile(pdfdoc_path):
            with open(pdfdoc_path, 'r', encoding='utf-8', errors='ignore') as f:
                pdf_html_content = f.read()
        else:
            print(la7mar + f"[AVISO] {pdfdoc_path} não encontrado. PDF não será gerado." + labyadh)
            pdf_enabled = False
            pdf_html_content = ""
    else:
        pdf_enabled = False
        pdf_html_content = ""

    foo = [la7mar, lazra9, la5dhar, movv, lasfar, cyan]
    color_choice = random.choice(foo)

    print(color_choice + "Como deseja enviar?\n  [1] Via Rede Local (Sem Proxy)\n  [2] Via Proxy (SOCKS5)\n")
    while True:
        choice_proxy = input("Escolha: ").strip()
        if choice_proxy == "1":
            use_proxy = False
            print(la5dhar + "Você optou por enviar SEM proxy (Rede Local). Se cair em RBL, reinicia modem." + labyadh)
            debug_log("Modo de envio: Rede Local (sem proxy).")
            break
        elif choice_proxy == "2":
            use_proxy = True
            print(la5dhar + "Você optou por enviar VIA PROXY (SOCKS5)." + labyadh)
            debug_log("Modo de envio: Via Proxy (SOCKS5).")
            break
        else:
            print(la7mar + "Opção inválida. Digite 1 ou 2." + labyadh)

    debug_log("Carregando SMTPS...")
    SmtpListMem[:] = load_smtps()

    if use_proxy:
        debug_log("Carregando Proxies...")
        ProxyListMem[:] = load_proxies()

    for s in SmtpListMem:
        usage_count[s] = 0
        paused_until[s] = 0

    # Configura chunk BCC
    try:
        csize = input(color_choice + "[?] Quantos emails por disparo (chunk BCC)? -> " + labyadh)
        if not csize.strip():
            chunk_bcc_size = 1
        else:
            chunk_bcc_size = int(csize)
        if chunk_bcc_size < 1:
            chunk_bcc_size = 1
    except:
        chunk_bcc_size = 1

    # Limite de envios por SMTP
    try:
        limit_per_smtp = int(input(color_choice + "[?] Limite de envios por SMTP? -> " + labyadh))
    except:
        limit_per_smtp = 100

    # Pausa após atingir limite
    try:
        pause_hours = float(input(color_choice + "[?] Pausa (horas) após limite? -> " + labyadh))
        pause_seconds = int(pause_hours * 3600)
    except:
        pause_seconds = 3600

    # Delay entre envios
    try:
        delay_between_sends = float(input(color_choice + "[?] Segundos de pausa entre disparos? -> " + labyadh))
    except:
        delay_between_sends = 2.0

    debug_log(f"Config -> pdf_enabled={pdf_enabled}, chunk={chunk_bcc_size}, "
              f"limit={limit_per_smtp}, pause={pause_seconds}s, delay={delay_between_sends}")

    # Número de threads
    th_str = input(color_choice + "[?] Quantidade de Threads? (padrão=10): " + labyadh)
    if not th_str.isdigit() or th_str == '':
        th = 10
    else:
        th = int(th_str)

    print(color_choice + "O que você deseja enviar?\n  [1] Enviar Emails\n  [2] Enviar Email -> SMS\n")
    messageQ = input("Sua opção: " + labyadh)

    if messageQ == '1':
        Email_List = input(color_choice + "[?] Arquivo de Emails (ex.: emails.txt): " + labyadh)
        if not os.path.isfile(Email_List):
            print(la7mar + f"[ERRO] Arquivo {Email_List} não encontrado." + labyadh)
            return

        with open(Email_List, 'r', encoding='utf-8', errors='ignore') as f:
            emails_all = [line.strip() for line in f if line.strip()]

        count = len(emails_all)
        if count == 0:
            print(la7mar + "[ERRO] Lista de Emails vazia!" + labyadh)
            return

        debug_log(f"Iniciando envio de Emails -> total={count}, threads={th}, chunk={chunk_bcc_size}")

        chunks = list(chunkify(emails_all, chunk_bcc_size))
        pool = ThreadPool(th)
        pool.map(ProcessEmailsChunk, chunks)
        pool.close()
        pool.join()

        ShowReport()

    elif messageQ == '2':
        SMS_List = input(color_choice + "[?] Arquivo de SMS (ex.: sms.txt): " + labyadh)
        if not os.path.isfile(SMS_List):
            print(la7mar + f"[ERRO] Arquivo {SMS_List} não encontrado." + labyadh)
            return

        with open(SMS_List, 'r', encoding='utf-8', errors='ignore') as f:
            sms_all = [line.strip() for line in f if line.strip()]

        count = len(sms_all)
        if count == 0:
            print(la7mar + "[ERRO] Lista de SMS vazia!" + labyadh)
            return

        debug_log(f"Iniciando envio de SMS -> total={count}, threads={th}, chunk={chunk_bcc_size}")

        chunks = list(chunkify(sms_all, chunk_bcc_size))
        pool = ThreadPool(th)
        pool.map(ProcessSMSChunk, chunks)
        pool.close()
        pool.join()

        ShowReport()

    else:
        print(movv + "Opção inválida! Escolha 1 ou 2." + labyadh)
        sys.exit(1)


if __name__ == '__main__':
    # Se quiser limpar o LOG anterior
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    cls()
    print_logo()
    Choose()
