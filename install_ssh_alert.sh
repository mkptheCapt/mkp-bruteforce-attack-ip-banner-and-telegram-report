#!/bin/bash

# --- Kurulum Sabitleri ---
CONFIG_DIR="/etc/ssh-alert"
STATE_DIR="/var/lib/ssh-alert"
CONFIG_FILE="${CONFIG_DIR}/config.json"
SCRIPT_FILE="${CONFIG_DIR}/ssh_alert.py"
SERVICE_FILE="/etc/systemd/system/ssh-telegram-alert.service"
TIMER_FILE="/etc/systemd/system/ssh-telegram-alert.timer"
FAIL2BAN_JAIL="/etc/fail2ban/jail.local"

# --- Ayarlar ---
REPORT_PERIOD=3600 # Saniye (60 dakika)
MAX_RETRY=6        # Fail2Ban maxretry
BAN_TIME="2400h"   # Fail2Ban yasaklama süresi (100 gün)

# --- Renkler ve Çıktı Fonksiyonları ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# --- 1. Kullanıcıdan Bilgi Alma ---
read_user_input() {
    log_info "--------------------------------------------------------"
    log_info "   SSH Saldırı Raporlama ve Önleme Sistemi Kurulumu"
    log_info "--------------------------------------------------------"
    
    # Telegram Bot Token'ı iste
    while [[ -z "$TELEGRAM_TOKEN" ]]; do
        read -p "$(echo -e "${YELLOW}Telegram Bot Token (Örn: 1234...:AAABBB...):${NC} ")" TELEGRAM_TOKEN
        if [[ -z "$TELEGRAM_TOKEN" ]]; then
            log_error "Bot Token boş bırakılamaz. Lütfen tekrar giriniz."
        fi
    done

    # Telegram Chat ID'yi iste
    while [[ -z "$CHAT_ID" ]]; do
        read -p "$(echo -e "${YELLOW}Telegram Chat ID (Örn: 1068...):${NC} ")" CHAT_ID
        if [[ -z "$CHAT_ID" ]]; then
            log_error "Chat ID boş bırakılamaz. Lütfen tekrar giriniz."
        fi
    done
}

# --- 2. Fail2Ban Kurulumu ve Ayarı ---
setup_fail2ban() {
    log_info "BÖLÜM 1: Fail2Ban Kurulumu ve Yapılandırması Başlatılıyor..."

    # a. Kurulum
    sudo apt update > /dev/null
    sudo apt install fail2ban -y > /dev/null
    
    # b. jail.local oluşturma ve temiz konfigürasyonu uygulama
    if [ -f /etc/fail2ban/jail.local ]; then
        log_warn "jail.local dosyası mevcut, yedekleniyor..."
        sudo mv /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
    fi
    
    log_info "Fail2Ban ayar dosyası (${FAIL2BAN_JAIL}) oluşturuluyor."
    
    sudo tee "${FAIL2BAN_JAIL}" > /dev/null <<EOF
[DEFAULT]
# IP yasaklama süresi: ${BAN_TIME} (100 gün)
bantime = ${BAN_TIME}
ignoreip = 127.0.0.1/8 ::1

[sshd]
# SSH korumasını etkinleştir
enabled = true
# Maksimum hatalı deneme sayısı
maxretry = ${MAX_RETRY}
EOF
    
    # c. Servisi başlatma
    log_info "Fail2Ban servisi yeniden başlatılıyor..."
    sudo systemctl restart fail2ban
    sudo systemctl enable fail2ban > /dev/null

    if sudo systemctl is-active --quiet fail2ban; then
        log_info "Fail2Ban başarılı şekilde çalışıyor. (${MAX_RETRY} denemede ${BAN_TIME} yasaklama ayarlandı.)"
    else
        log_error "Fail2Ban başlatılamadı! Lütfen manuel olarak kontrol edin: sudo systemctl status fail2ban"
        exit 1
    fi
}

# --- 3. Python Betiği ve Config Dosyaları ---
setup_python_script() {
    log_info "BÖLÜM 2: Python Raporlama Betiği Kurulumu Başlatılıyor..."

    # a. Dizinleri oluştur
    sudo mkdir -p "${CONFIG_DIR}"
    sudo mkdir -p "${STATE_DIR}"
    log_info "Yapılandırma dizinleri oluşturuldu."

    # b. Config.json oluştur (Kullanıcı girdilerini kullan)
    log_info "Konfigürasyon dosyası (${CONFIG_FILE}) oluşturuluyor."
    sudo tee "${CONFIG_FILE}" > /dev/null <<JSON
{
  "telegram_token": "${TELEGRAM_TOKEN}",
  "telegram_chat_id": "${CHAT_ID}",
  "report_period_seconds": ${REPORT_PERIOD},
  "log_path": "/var/log/auth.log"
}
JSON

    # c. Python betiğini oluştur
    log_info "Python betiği (${SCRIPT_FILE}) oluşturuluyor..."
    # Burası Python kodu, girinti hatalarından kaçınmak için tırnak içinde
    sudo tee "${SCRIPT_FILE}" > /dev/null <<'PY'
#!/usr/bin/env python3
import time, re, json, os, sys
from urllib.parse import urlencode
from urllib.request import urlopen, Request
from datetime import datetime

# --- Sabitler ---
CONFIG_PATH = "/etc/ssh-alert/config.json"
STATE_PATH = "/var/lib/ssh-alert/state.json"
LOG_PATH = "/var/log/auth.log"
FAIL2BAN_LOG_PATH = "/var/log/fail2ban.log"

# --- Konfigürasyonu Yükle ---
try:
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
except Exception as e:
    print(f"Cannot load config: {e}")
    sys.exit(1)

TOKEN = cfg.get("telegram_token")
CHAT_ID = str(cfg.get("telegram_chat_id"))
REPORT_PERIOD = int(cfg.get("report_period_seconds", 3600)) 
AUTH_LOG_PATH = cfg.get("log_path", LOG_PATH)

# --- Durum Yönetimi ---
def load_state():
    try:
        with open(STATE_PATH, 'r') as f:
            return json.load(f)
    except:
        one_hour_ago = int(time.time()) - REPORT_PERIOD
        # last_log_pos: Log dosyasının başına ayarlanır (ilk çalıştırmada tüm logları okumamak için)
        return {'last_report_time': one_hour_ago, 'last_log_pos': 0}

def save_state(state):
    try:
        with open(STATE_PATH, 'w') as f:
            json.dump(state, f)
    except Exception as e:
        print(f"State save error: {e}")

# --- Telegram Fonksiyonu ---
def send_telegram_message(message):
    if not TOKEN or not CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    params = urlencode({
        'chat_id': CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown'
    })
    try:
        urlopen(Request(url, params.encode('utf8'))).read()
        print("Telegram mesajı başarıyla gönderildi.")
    except Exception as e:
        print(f"Telegram send error: {e}")

# --- Log Okuma ve Analiz ---
def check_logs():
    state = load_state()
    current_time = int(time.time())
    
    if current_time - state.get('last_report_time', 0) < REPORT_PERIOD:
        print("Raporlama periyodu dolmadı. Çıkılıyor.")
        return

    report_start_timestamp = state['last_report_time']
    report_start_dt = datetime.fromtimestamp(report_start_timestamp)

    failed_attempts = {}
    # Dikkat: Python'da \s+ gibi ifadeler için raw string (r'...') kullanmak en iyisidir
    fail_pattern = re.compile(r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*Failed password for (?:invalid user )?(\S+) from (\S+)')
    
    banned_ips = set()
    ban_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*NOTICE\s+\[sshd\]\s+Ban\s+(\S+)')

    # --- auth.log Okuma ---
    new_log_pos = state['last_log_pos']
    try:
        with open(AUTH_LOG_PATH, 'r') as f:
            f.seek(state['last_log_pos'])
            new_logs = f.readlines()
            new_log_pos = f.tell() 
            
            for line in new_logs:
                try:
                    log_month_day = line[:6].strip()
                    log_time = line[7:15].strip()
                    log_year = str(datetime.now().year)
                    log_dt = datetime.strptime(f"{log_month_day} {log_year} {log_time}", "%b %d %Y %H:%M:%S")
                except ValueError:
                    continue

                if log_dt > report_start_dt:
                    match = fail_pattern.search(line)
                    if match:
                        timestamp_str, username, ip_address = match.groups()
                        
                        if ip_address not in failed_attempts:
                            failed_attempts[ip_address] = {'users': set(), 'count': 0}
                        
                        failed_attempts[ip_address]['users'].add(username)
                        # Hata düzeltildi: IP'nin sayımını artır
                        failed_attempts[ip_address]['count'] += 1 

    except Exception as e:
        print(f"Auth log file error: {e}")

    # --- fail2ban.log Okuma ---
    try:
        with open(FAIL2BAN_LOG_PATH, 'r') as f:
            for line in f:
                match = ban_pattern.search(line)
                if match:
                    timestamp_str, ip_address = match.groups()
                    log_dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    if log_dt > report_start_dt:
                        banned_ips.add(ip_address)
    except FileNotFoundError:
        print("Fail2Ban log dosyası bulunamadı.")
    except Exception as e:
        print(f"Fail2Ban log file error: {e}")

    # --- Rapor Oluşturma ve Gönderme ---
    # Python 3.8+ için, sum ile daha kısa ve temiz
    total_failed_count = sum(data['count'] for data in failed_attempts.values())
    
    if total_failed_count > 0 or banned_ips:
        header = f"🚨 *SSH Saldırı Raporu* 🚨\n"
        header += f"Sunucu: `{os.uname().nodename}`\n\n"
        header += f"Rapor Dönemi: *Son 60 Dakika* (`{report_start_dt.strftime('%H:%M %d %b')}` - `{datetime.now().strftime('%H:%M %d %b')}`)\n\n"
        
        failed_summary = f"*1. Başarısız Giriş Denemeleri:* (Toplam {total_failed_count} deneme)\n"
        if total_failed_count > 0:
            for ip, data in failed_attempts.items():
                user_list = ", ".join(sorted(list(data['users'])))
                # Düzeltilmiş format: 'kez' yerine 'deneme'
                failed_summary += f" • IP: `{ip}` ({data['count']} deneme). Kullanıcılar: {user_list}\n"
        else:
            failed_summary += " • Başarısız deneme bulunamadı.\n"
        
        banned_summary = f"\n*2. Fail2Ban ile Yasaklanan IP'ler:* (Toplam {len(banned_ips)} yeni yasaklama)\n"
        if banned_ips:
            for ip in sorted(list(banned_ips)):
                banned_summary += f" • `{ip}`\n"
            # Hata düzeltildi: BAN_TIME değişkeni kaldırıldı ve sabit değer yazıldı
            banned_summary += f"\nYasaklama süresi: 2400 saat (Fail2Ban ayarı)\n"
        else:
            banned_summary += " • Bu dönemde yeni IP yasaklanmadı.\n"
            
        full_message = header + failed_summary + banned_summary
        
        send_telegram_message(full_message)
        state['last_report_time'] = current_time 
        
    else:
        print("Raporlanacak olay bulunamadı. Mesaj gönderilmedi.")
        
    state['last_log_pos'] = new_log_pos
    save_state(state)

if __name__ == "__main__":
    check_logs()

# Python kodunu sonlandıran etiket (girintisiz olmalı)
PY

    # d. Betik izinlerini ayarla
    sudo chmod +x "${SCRIPT_FILE}"

    # e. Durum dosyasını hazırla
    log_info "Durum dosyası (${STATE_DIR}/state.json) hazırlanıyor..."
    sudo touch "${STATE_DIR}/state.json"
    sudo chown root:root "${STATE_DIR}/state.json"
    sudo chmod 600 "${STATE_DIR}/state.json"

}

# --- 4. Systemd Ayarları ---
setup_systemd() {
    log_info "BÖLÜM 3: Systemd Servis ve Zamanlayıcı Ayarları Başlatılıyor..."

    # a. Service birimi oluştur
    log_info "Servis dosyası (${SERVICE_FILE}) oluşturuluyor."
    sudo tee "${SERVICE_FILE}" > /dev/null <<EOF
[Unit]
Description=SSH Failed Login Telegram Alert

[Service]
Type=oneshot 
# KRİTİK DÜZELTME: Betiği açıkça Python 3 ile çalıştırıyoruz
ExecStart=/usr/bin/python3 ${SCRIPT_FILE}
User=root

[Install]
WantedBy=multi-user.target
EOF

    # b. Timer birimi oluştur
    log_info "Zamanlayıcı dosyası (${TIMER_FILE}) oluşturuluyor."
    sudo tee "${TIMER_FILE}" > /dev/null <<EOF
[Unit]
Description=Run SSH Failed Login Telegram Alert Hourly

[Timer]
OnUnitActiveSec=60min
OnBootSec=1min

[Install]
WantedBy=timers.target
EOF

    # c. Servisleri başlat
    log_info "Systemd ayarları yeniden yükleniyor ve zamanlayıcı başlatılıyor..."
    sudo systemctl daemon-reload
    sudo systemctl enable --now ssh-telegram-alert.timer
    
    if sudo systemctl is-active --quiet ssh-telegram-alert.timer; then
        log_info "Zamanlayıcı başarılı şekilde başlatıldı ve çalışıyor."
    else
        log_error "Zamanlayıcı başlatılamadı! Lütfen kontrol edin: sudo systemctl status ssh-telegram-alert.timer"
        exit 1
    fi
}

# --- Ana Çalışma Akışı ---
main() {
    read_user_input
    setup_fail2ban
    setup_python_script
    setup_systemd
    
    log_info "--------------------------------------------------------"
    log_info "${GREEN}Kurulum Başarılı!${NC}"
    log_info "--------------------------------------------------------"
    log_info "Raporlama her 60 dakikada bir otomatik çalışacaktır."
    log_info "Manuel test çalıştırması için: sudo systemctl start ssh-telegram-alert.service"
    log_info "Fail2Ban durumu: sudo systemctl status fail2ban"
    log_info "Raporlama durumu: sudo systemctl status ssh-telegram-alert.timer"
}

main "$@"
