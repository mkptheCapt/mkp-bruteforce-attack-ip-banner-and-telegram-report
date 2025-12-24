
#!/bin/bash
# ------------------------------------------------------------
# SSH saldırı raporlama + Fail2Ban kurulum betiği (güncellenmiş)
# Türkçe açıklamalar içerir ve etkileşimli yardım menüsü ekler.
# ------------------------------------------------------------

# --- Kurulum Sabitleri ---
CONFIG_DIR="/etc/ssh-alert"
STATE_DIR="/var/lib/ssh-alert"
CONFIG_FILE="${CONFIG_DIR}/config.json"
SCRIPT_FILE="${CONFIG_DIR}/ssh_alert.py"
SERVICE_FILE="/etc/systemd/system/ssh-telegram-alert.service"
TIMER_FILE="/etc/systemd/system/ssh-telegram-alert.timer"
FAIL2BAN_JAIL="/etc/fail2ban/jail.local"
HELP_BIN="/usr/local/bin/help_ipban"   # Yardım komutu adı

# --- Varsayılan Ayarlar (kullanıcı kurulumda değiştirecek) ---
DEFAULT_REPORT_MIN=60       # Raporlama her 60 dakikada bir (varsayılan)
DEFAULT_MAX_RETRY=6         # Fail2Ban maxretry varsayılanı
DEFAULT_BAN_HOURS=2400      # Bantime 2400 saat (100 gün)

# --- Renkler ve Çıktı Fonksiyonları ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() {  echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() {  echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error(){  echo -e "${RED}[ERROR]${NC} $1"; }

# ------------------------------------------------------------
# 1) Kullanıcıdan Bilgi Alma
# ------------------------------------------------------------
read_user_input() {
  log_info "------------------------------------------------------------"
  log_info " SSH Saldırı Raporlama ve Önleme Sistemi Kurulumu"
  log_info "------------------------------------------------------------"

  # Telegram Bot Token'ı iste
  while [[ -z "$TELEGRAM_TOKEN" ]]; do
    read -p "$(echo -e "${YELLOW}Telegram Bot Token (Örn: 1234...:AAABBB...):${NC} ")" TELEGRAM_TOKEN
    [[ -z "$TELEGRAM_TOKEN" ]] && log_error "Bot Token boş bırakılamaz. Lütfen tekrar giriniz."
  done

  # Telegram Chat/Group ID'yi iste (gruplar için genelde -100 ile başlar)
  while [[ -z "$CHAT_ID" ]]; do
    read -p "$(echo -e "${YELLOW}Telegram Chat/Group ID (Örn: -1001234567890):${NC} ")" CHAT_ID
    [[ -z "$CHAT_ID" ]] && log_error "Chat/Group ID boş bırakılamaz. Lütfen tekrar giriniz."
  done

  # Raporlama periyodu (dakika)
  while :; do
    read -p "$(echo -e "${YELLOW}Raporlama kaç dakikada bir olsun? (varsayılan: ${DEFAULT_REPORT_MIN}):${NC} ")" REPORT_PERIOD_MIN
    REPORT_PERIOD_MIN="${REPORT_PERIOD_MIN:-$DEFAULT_REPORT_MIN}"
    if [[ "$REPORT_PERIOD_MIN" =~ ^[1-9][0-9]*$ ]]; then
      break
    else
      log_error "Lütfen 1 veya daha büyük bir tam sayı giriniz (dakika)."
    fi
  done
  REPORT_PERIOD=$((REPORT_PERIOD_MIN * 60))  # saniye cinsinden config'e yazacağız

  # Fail2Ban maxretry
  while :; do
    read -p "$(echo -e "${YELLOW}Kaç hatalı girişte IP yasaklansın? (varsayılan: ${DEFAULT_MAX_RETRY}):${NC} ")" MAX_RETRY
    MAX_RETRY="${MAX_RETRY:-$DEFAULT_MAX_RETRY}"
    if [[ "$MAX_RETRY" =~ ^[1-9][0-9]*$ ]]; then
      break
    else
      log_error "Lütfen 1 veya daha büyük bir tam sayı giriniz (deneme sayısı)."
    fi
  done

  # Fail2Ban bantime (saat)
  while :; do
    read -p "$(echo -e "${YELLOW}IP yasaklama süresi kaç saat olsun? (varsayılan: ${DEFAULT_BAN_HOURS}):${NC} ")" BAN_TIME_HOURS
    BAN_TIME_HOURS="${BAN_TIME_HOURS:-$DEFAULT_BAN_HOURS}"
    if [[ "$BAN_TIME_HOURS" =~ ^[1-9][0-9]*$ ]]; then
      break
    else
      log_error "Lütfen 1 veya daha büyük bir tam sayı giriniz (saat)."
    fi
  done
  BAN_TIME="${BAN_TIME_HOURS}h"
}

# ------------------------------------------------------------
# 2) Fail2Ban Kurulumu ve Ayarı
# ------------------------------------------------------------
setup_fail2ban() {
  log_info "BÖLÜM 1: Fail2Ban Kurulumu ve Yapılandırması Başlatılıyor..."
  sudo apt update >/dev/null
  sudo apt install -y fail2ban >/dev/null

  # Mevcut jail.local varsa yedekle
  if [[ -f "$FAIL2BAN_JAIL" ]]; then
    log_warn "jail.local dosyası mevcut, yedekleniyor..."
    sudo mv "$FAIL2BAN_JAIL" "${FAIL2BAN_JAIL}.bak"
  fi

  # Fail2Ban ayar dosyasını oluştur
  log_info "Fail2Ban ayar dosyası (${FAIL2BAN_JAIL}) oluşturuluyor."
  sudo tee "${FAIL2BAN_JAIL}" >/dev/null <<EOF
[DEFAULT]
# IP yasaklama süresi: ${BAN_TIME_HOURS} saat
bantime = ${BAN_TIME}
ignoreip = 127.0.0.1/8 ::1

[sshd]
# SSH korumasını etkinleştir
enabled = true
# Maksimum hatalı deneme sayısı
maxretry = ${MAX_RETRY}
EOF

  log_info "Fail2Ban servisi yeniden başlatılıyor..."
  sudo systemctl restart fail2ban
  sudo systemctl enable fail2ban >/dev/null
  if sudo systemctl is-active --quiet fail2ban; then
    log_info "Fail2Ban çalışıyor. (maxretry=${MAX_RETRY}, bantime=${BAN_TIME})"
  else
    log_error "Fail2Ban başlatılamadı! Kontrol edin: sudo systemctl status fail2ban"
    exit 1
  fi
}

# ------------------------------------------------------------
# 3) Python Betiği ve Config Dosyaları
# ------------------------------------------------------------
setup_python_script() {
  log_info "BÖLÜM 2: Python Raporlama Betiği Kurulumu Başlatılıyor..."

  # Dizinleri oluştur
  sudo mkdir -p "${CONFIG_DIR}"
  sudo mkdir -p "${STATE_DIR}"

  log_info "Konfigürasyon dosyası (${CONFIG_FILE}) oluşturuluyor."
  sudo tee "${CONFIG_FILE}" >/dev/null <<JSON
{
  "telegram_token": "${TELEGRAM_TOKEN}",
  "telegram_chat_id": "${CHAT_ID}",
  "report_period_seconds": ${REPORT_PERIOD},
  "ban_time_hours": ${BAN_TIME_HOURS},
  "max_retry": ${MAX_RETRY},
  "log_path": "/var/log/auth.log"
}
JSON

  log_info "Python betiği (${SCRIPT_FILE}) oluşturuluyor..."
  sudo tee "${SCRIPT_FILE}" >/dev/null <<'PY'
#!/usr/bin/env python3
# Türkçe açıklamalar: SSH saldırı raporlama betiği
import time, re, json, os, sys
from urllib.parse import urlencode
from urllib.request import urlopen, Request
from datetime import datetime

# Sabit yollar
CONFIG_PATH = "/etc/ssh-alert/config.json"
STATE_PATH  = "/var/lib/ssh-alert/state.json"
AUTH_LOG_DEFAULT = "/var/log/auth.log"
FAIL2BAN_LOG_PATH = "/var/log/fail2ban.log"

# Konfigürasyonu yükle
try:
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
except Exception as e:
    print(f"Config yüklenemedi: {e}")
    sys.exit(1)

TOKEN = cfg.get("telegram_token")
CHAT_ID = str(cfg.get("telegram_chat_id"))
REPORT_PERIOD = int(cfg.get("report_period_seconds", 3600))
AUTH_LOG_PATH = cfg.get("log_path", AUTH_LOG_DEFAULT)
BAN_TIME_HOURS = int(cfg.get("ban_time_hours", 2400))
MAX_RETRY = int(cfg.get("max_retry", 6))

# Durum yönetimi
def load_state():
    try:
        with open(STATE_PATH, 'r') as f:
            return json.load(f)
    except:
        now = int(time.time())
        return {'last_report_time': now - REPORT_PERIOD, 'last_log_pos': 0}

def save_state(state):
    try:
        with open(STATE_PATH, 'w') as f:
            json.dump(state, f)
    except Exception as e:
        print(f"State kaydetme hatası: {e}")

# Telegram gönderimi
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
        print("Telegram mesajı gönderildi.")
    except Exception as e:
        print(f"Telegram gönderim hatası: {e}")

# Log kontrolü
def check_logs():
    state = load_state()
    current_time = int(time.time())
    if current_time - state.get('last_report_time', 0) < REPORT_PERIOD:
        print("Raporlama periyodu dolmadı. Çıkılıyor.")
        return

    report_start_ts = state['last_report_time']
    report_start_dt = datetime.fromtimestamp(report_start_ts)

    failed_attempts = {}
    # auth.log desenleri (Failed password for .. from ..)
    fail_pattern = re.compile(r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*Failed password for (?:invalid user )?(\S+) from (\S+)')
    banned_ips = set()
    ban_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*NOTICE\s+\[sshd\]\s+Ban\s+(\S+)')

    # auth.log oku (sadece yeni satırlar)
    new_log_pos = state['last_log_pos']
    try:
        with open(AUTH_LOG_PATH, 'r') as f:
            f.seek(state['last_log_pos'])
            new_logs = f.readlines()
            new_log_pos = f.tell()
            for line in new_logs:
                try:
                    # Ay/gün ve saat formatını çıkar (ör: "Dec 23 13:05:12")
                    log_month_day = line[:6].strip()
                    log_time = line[7:15].strip()
                    log_year = str(datetime.now().year)
                    log_dt = datetime.strptime(f"{log_month_day} {log_year} {log_time}", "%b %d %Y %H:%M:%S")
                except ValueError:
                    continue
                if log_dt > report_start_dt:
                    match = fail_pattern.search(line)
                    if match:
                        _, username, ip_address = match.groups()
                        if ip_address not in failed_attempts:
                            failed_attempts[ip_address] = {'users': set(), 'count': 0}
                        failed_attempts[ip_address]['users'].add(username)
                        failed_attempts[ip_address]['count'] += 1
    except Exception as e:
        print(f"auth.log okuma hatası: {e}")

    # fail2ban.log oku (yeni Ban kayıtlarını topla)
    try:
        with open(FAIL2BAN_LOG_PATH, 'r') as f:
            for line in f:
                m = ban_pattern.search(line)
                if m:
                    ts_str, ip = m.groups()
                    log_dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    if log_dt > report_start_dt:
                        banned_ips.add(ip)
    except FileNotFoundError:
        print("Fail2Ban log dosyası bulunamadı.")
    except Exception as e:
        print(f"fail2ban.log okuma hatası: {e}")

    total_failed_count = sum(data['count'] for data in failed_attempts.values())
    period_min = REPORT_PERIOD // 60

    if total_failed_count > 0 or banned_ips:
        header = "🚨 *SSH Saldırı Raporu* 🚨\n"
        header += f"Sunucu: `{os.uname().nodename}`\n\n"
        header += f"Rapor Dönemi: *Son {period_min} Dakika* (`{report_start_dt.strftime('%H:%M %d %b')}` - `{datetime.now().strftime('%H:%M %d %b')}`)\n\n"

        failed_summary = f"*1. Başarısız Giriş Denemeleri:* (Toplam {total_failed_count} deneme)\n"
        if total_failed_count > 0:
            for ip, data in failed_attempts.items():
                user_list = ", ".join(sorted(list(data['users'])))
                failed_summary += f" • IP: `{ip}` ({data['count']} deneme). Kullanıcılar: {user_list}\n"
        else:
            failed_summary += " • Başarısız deneme bulunamadı.\n"

        banned_summary = f"\n*2. Fail2Ban ile Yasaklanan IP'ler:* (Toplam {len(banned_ips)} yeni yasaklama)\n"
        if banned_ips:
            for ip in sorted(list(banned_ips)):
                banned_summary += f" • `{ip}`\n"
            banned_summary += f"\nYasaklama süresi: {BAN_TIME_HOURS} saat (Fail2Ban ayarı)\n"
        else:
            banned_summary += " • Bu dönemde yeni IP yasaklanmadı.\n"

        full_message = header + failed_summary + banned_summary
        send_telegram_message(full_message)
        state['last_report_time'] = current_time
    else:
        print("Raporlanacak olay yok. Mesaj gönderilmedi.")

    state['last_log_pos'] = new_log_pos
    save_state(state)

if __name__ == "__main__":
    check_logs()
PY

  # İzinler
  sudo chmod +x "${SCRIPT_FILE}"

  # Durum dosyası
  log_info "Durum dosyası (${STATE_DIR}/state.json) hazırlanıyor..."
  sudo touch "${STATE_DIR}/state.json"
  sudo chown root:root "${STATE_DIR}/state.json"
  sudo chmod 600 "${STATE_DIR}/state.json"
}

# ------------------------------------------------------------
# 4) Systemd Ayarları
# ------------------------------------------------------------
setup_systemd() {
  log_info "BÖLÜM 3: Systemd Servis ve Zamanlayıcı Ayarları Başlatılıyor..."

  # Service birimi
  log_info "Servis dosyası (${SERVICE_FILE}) oluşturuluyor."
  sudo tee "${SERVICE_FILE}" >/dev/null <<EOF
[Unit]
Description=SSH Failed Login Telegram Alert

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 ${SCRIPT_FILE}
User=root

[Install]
WantedBy=multi-user.target
EOF

  # Timer birimi (kullanıcının verdiği dakika ile)
  log_info "Zamanlayıcı dosyası (${TIMER_FILE}) oluşturuluyor (her ${REPORT_PERIOD_MIN} dakikada)."
  sudo tee "${TIMER_FILE}" >/dev/null <<EOF
[Unit]
Description=Run SSH Failed Login Telegram Alert every ${REPORT_PERIOD_MIN} minutes

[Timer]
OnUnitActiveSec=${REPORT_PERIOD_MIN}min
OnBootSec=1min

[Install]
WantedBy=timers.target
EOF

  # Servisleri başlat
  log_info "Systemd ayarları yeniden yükleniyor ve zamanlayıcı başlatılıyor..."
  sudo systemctl daemon-reload
  sudo systemctl enable --now ssh-telegram-alert.timer

  if sudo systemctl is-active --quiet ssh-telegram-alert.timer; then
    log_info "Zamanlayıcı başlatıldı ve çalışıyor."
  else:
    log_error "Zamanlayıcı başlatılamadı! Kontrol edin: sudo systemctl status ssh-telegram-alert.timer"
    exit 1
  fi
}

# ------------------------------------------------------------
# 5) Yardım / Ayar Menüsü Scripti (help_ipban)
# ------------------------------------------------------------
install_help_menu() {
  log_info "Yardım menüsü (${HELP_BIN}) oluşturuluyor..."

  sudo tee "${HELP_BIN}" >/dev/null <<'HB'
#!/bin/bash
# --- Türkçe açıklamalar içeren yardım/ayar menüsü ---
CONFIG_DIR="/etc/ssh-alert"
STATE_DIR="/var/lib/ssh-alert"
CONFIG_FILE="${CONFIG_DIR}/config.json"
SCRIPT_FILE="${CONFIG_DIR}/ssh_alert.py"
SERVICE_FILE="/etc/systemd/system/ssh-telegram-alert.service"
TIMER_FILE="/etc/systemd/system/ssh-telegram-alert.timer"
FAIL2BAN_JAIL="/etc/fail2ban/jail.local"
HELP_BIN="/usr/local/bin/help_ipban"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} Lütfen root veya sudo ile çalıştırın (örn: sudo help_ipban)."
    exit 1
  fi
}

# --- JSON yardımcıları (Python kullanıyoruz; jq bağımlılığı yok) ---
json_set() {
  local key="$1"; local value="$2"
  python3 - "$CONFIG_FILE" "$key" "$value" <<'PY'
import json,sys
cfg_path,key,value=sys.argv[1],sys.argv[2],sys.argv[3]
try: v=int(value)
except ValueError: v=value
with open(cfg_path) as f: cfg=json.load(f)
cfg[key]=v
with open(cfg_path,"w") as f: json.dump(cfg,f,indent=2)
print("OK")
PY
}

json_get() {
  local key="$1"
  python3 - "$CONFIG_FILE" "$key" <<'PY'
import json,sys
cfg_path,key=sys.argv[1],sys.argv[2]
try:
    with open(cfg_path) as f:
        cfg=json.load(f)
    v=cfg.get(key,"")
    print(v if v is not None else "")
except Exception:
    print("")
PY
}

show_settings() {
  echo -e "${GREEN}--- Mevcut Ayarlar ---${NC}"
  echo "Ayarların kayıt yeri:"
  echo "  - Config: ${CONFIG_FILE}"
  echo "  - Fail2Ban: ${FAIL2BAN_JAIL}"
  echo "  - systemd Servis: ${SERVICE_FILE}"
  echo "  - systemd Timer:  ${TIMER_FILE}"
  echo
  echo "Config içerik (özet):"
  python3 - <<PY
import json
try:
    with open("${CONFIG_FILE}") as f:
        cfg=json.load(f)
    print("  telegram_token       :", "(gizli)")
    print("  telegram_chat_id     :", cfg.get("telegram_chat_id"))
    print("  report_period_seconds:", cfg.get("report_period_seconds"))
    print("  ban_time_hours       :", cfg.get("ban_time_hours"))
    print("  max_retry            :", cfg.get("max_retry"))
    print("  log_path             :", cfg.get("log_path"))
except Exception as e:
    print("  Config okunamadı:", e)
PY
  echo
  echo "Fail2Ban jail.local özeti:"
  grep -E '^(bantime|maxretry|enabled|ignoreip)' "${FAIL2BAN_JAIL}" 2>/dev/null || echo "  jail.local okunamadı."
}

set_report_minutes() {
  require_root
  read -p "$(echo -e "${YELLOW}Yeni raporlama periyodu (dakika): ${NC}")" new_min
  if [[ ! "$new_min" =~ ^[1-9][0-9]*$ ]]; then
    echo -e "${RED}[ERROR]${NC} Geçersiz dakika değeri."
    return
  fi
  local new_sec=$((new_min*60))
  json_set "report_period_seconds" "$new_sec" >/dev/null
  sudo sed -i "s/^OnUnitActiveSec=.*/OnUnitActiveSec=${new_min}min/" "${TIMER_FILE}"
  sudo sed -i "s/^Description=.*/Description=Run SSH Failed Login Telegram Alert every ${new_min} minutes/" "${TIMER_FILE}"
  sudo systemctl daemon-reload
  sudo systemctl restart ssh-telegram-alert.timer
  echo -e "${GREEN}[OK]${NC} Raporlama periyodu ${new_min} dakikaya ayarlandı."
}

set_maxretry() {
  require_root
  read -p "$(echo -e "${YELLOW}Yeni maxretry (kaç hatalı girişte yasaklansın): ${NC}")" new_retry
  if [[ ! "$new_retry" =~ ^[1-9][0-9]*$ ]]; then
    echo -e "${RED}[ERROR]${NC} Geçersiz sayı."
    return
  fi
  json_set "max_retry" "$new_retry" >/dev/null
  sudo sed -i "s/^maxretry.*/maxretry = ${new_retry}/" "${FAIL2BAN_JAIL}"
  sudo systemctl restart fail2ban
  echo -e "${GREEN}[OK]${NC} maxretry=${new_retry} olarak ayarlandı ve Fail2Ban yeniden başlatıldı."
}

set_bantime_hours() {
  require_root
  read -p "$(echo -e "${YELLOW}Yeni bantime (saat): ${NC}")" new_hours
  if [[ ! "$new_hours" =~ ^[1-9][0-9]*$ ]]; then
    echo -e "${RED}[ERROR]${NC} Geçersiz saat değeri."
    return
  fi
  json_set "ban_time_hours" "$new_hours" >/dev/null
  sudo sed -i "s/^bantime.*/bantime = ${new_hours}h/" "${FAIL2BAN_JAIL}"
  sudo systemctl restart fail2ban
  echo -e "${GREEN}[OK]${NC} bantime=${new_hours}h olarak ayarlandı ve Fail2Ban yeniden başlatıldı."
}

set_log_path() {
  require_root
  read -p "$(echo -e "${YELLOW}Yeni log dosyası yolu (örn: /var/log/auth.log): ${NC}")" new_log
  if [[ -z "$new_log" ]]; then
    echo -e "${RED}[ERROR]${NC} Boş değer girilemez."
    return
  fi
  if [[ ! -f "$new_log" ]]; then
    echo -e "${YELLOW}[WARN]${NC} Dosya şu an bulunamadı, yine de ayarı kaydediyoruz."
  fi
  json_set "log_path" "$new_log" >/dev/null
  echo -e "${GREEN}[OK]${NC} log_path=${new_log} olarak ayarlandı (bir sonraki çalıştırmada kullanılacak)."
}

telegram_test_message() {
  require_root
  TOKEN=$(json_get "telegram_token")
  CHAT_ID=$(json_get "telegram_chat_id")
  if [[ -z "$TOKEN" || -z "$CHAT_ID" ]]; then
    echo -e "${RED}[ERROR]${NC} telegram_token veya telegram_chat_id config'te bulunamadı."
    return
  fi
  MSG="✅ Test: SSH uyarı sistemi çalışıyor. $(hostname) - $(date '+%Y-%m-%d %H:%M:%S')"
  if command -v curl >/dev/null 2>&1; then
    resp=$(curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
            -d "chat_id=${CHAT_ID}" -d "text=${MSG}" -d "parse_mode=Markdown")
    if [[ "$resp" == *"\"ok\":true"* ]]; then
      echo -e "${GREEN}[OK]${NC} Telegram test mesajı gönderildi."
    else
      echo -e "${RED}[ERROR]${NC} Telegram gönderim başarısız: $resp"
    fi
  else
    python3 - <<PY
from urllib.parse import urlencode
from urllib.request import urlopen, Request
TOKEN="${TOKEN}"; CHAT_ID="${CHAT_ID}"
MSG="${MSG}"
try:
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    params = urlencode({'chat_id': CHAT_ID, 'text': MSG, 'parse_mode': 'Markdown'})
    urlopen(Request(url, params.encode('utf8'))).read()
    print("OK")
except Exception as e:
    print("ERROR:", e)
PY
  fi
}

manual_run_now() {
  require_root
  sudo systemctl start ssh-telegram-alert.service
  echo -e "${GREEN}[OK]${NC} Manuel rapor tetiklendi. Telegram grubunuzu kontrol edin."
}

stop_program() {
  # --- Türkçe açıklama ---
  # Programın çalışmasını durdurmak için timer'ı durdurmak yeterlidir.
  # Servis oneshot olduğundan sadece tetiklenir; timer durunca raporlama da durur.
  require_root
  sudo systemctl stop ssh-telegram-alert.timer
  echo -e "${GREEN}[OK]${NC} Programın çalışması durduruldu."
  echo -e "Tekrar çalıştırmak için komut:"
  echo -e "  ${YELLOW}sudo systemctl start ssh-telegram-alert.timer${NC}"
}

uninstall_program() {
  require_root
  echo -e "${YELLOW}ip ban bruteforce attack programı silinecek emin misiniz? e/h${NC}"
  read -r answer
  case "$answer" in
    h|H)
      echo "İşlem iptal edildi. Menüye dönülüyor."
      return
      ;;
    e|E)
      echo "Silme işlemi başlatılıyor..."
      ;;
    *)
      echo "Geçersiz seçim. İşlem iptal edildi."
      return
      ;;
  esac

  # 1) Çalışan birimleri durdur/disable et
  sudo systemctl stop ssh-telegram-alert.timer 2>/dev/null
  sudo systemctl stop ssh-telegram-alert.service 2>/dev/null
  sudo systemctl disable ssh-telegram-alert.timer 2>/dev/null

  # 2) systemd unit dosyalarını sil
  sudo rm -f "${TIMER_FILE}" "${SERVICE_FILE}"
  sudo systemctl daemon-reload

  # 3) Fail2Ban konfigürasyonunu geri al
  if [[ -f "${FAIL2BAN_JAIL}.bak" ]]; then
    sudo mv "${FAIL2BAN_JAIL}.bak" "${FAIL2BAN_JAIL}"
    echo "Fail2Ban: yedek jail.local geri yüklendi."
  elif [[ -f "${FAIL2BAN_JAIL}" ]]; then
    sudo rm -f "${FAIL2BAN_JAIL}"
    echo "Fail2Ban: oluşturulan jail.local silindi."
  fi
  sudo systemctl restart fail2ban 2>/dev/null || true

  # 4) Program dosyalarını temizle
  sudo rm -rf "${CONFIG_DIR}" "${STATE_DIR}"

  # 5) Yardım komutunu sil (bu dosya)
  sudo rm -f "${HELP_BIN}"

  echo -e "${GREEN}[OK]${NC} Program ve ilişkili birimler sistemden kaldırıldı."
  echo "Gerekirse yeniden kurmak için kurulum betiğini (install_ssh_alert.sh) tekrar çalıştırabilirsiniz."
}

help_menu() {
  echo -e "${GREEN}============================================================${NC}"
  echo -e "${GREEN} help_ipban - SSH saldırı raporlama yardım/ayar menüsü ${NC}"
  echo -e "${GREEN}============================================================${NC}"
  echo "Ayarların kayıt yeri:"
  echo "  - Config: ${CONFIG_FILE}"
  echo "  - Fail2Ban: ${FAIL2BAN_JAIL}"
  echo "  - systemd Timer: ${TIMER_FILE}"
  echo
  echo "Menü:"
  echo "  1) Ayarları görüntüle"
  echo "  2) Raporlama kaç dakikada bir olsun? (değiştir)"
  echo "  3) Kaç hatalı girişte IP yasaklansın? (maxretry)"
  echo "  4) IP yasaklama süresi kaç saat olsun? (bantime)"
  echo "  5) Raporlamayı şimdi manuel tetikle"
  echo "  6) Telegram TEST mesajı gönder"
  echo "  7) Log dosyası yolunu değiştir (auth.log yolu)"
  echo "  8) IP ban programı çalışmasını durdur"
  echo "  9) IP ban programını durdur ve sistemden tamamen sil"
  echo "  q) Çıkış"
  echo

  while true; do
    read -p "Seçiminiz: " c
    case "$c" in
      1) show_settings ;;
      2) set_report_minutes ;;
      3) set_maxretry ;;
      4) set_bantime_hours ;;
      5) manual_run_now ;;
      6) telegram_test_message ;;
      7) set_log_path ;;
      8) stop_program ;;
      9) uninstall_program ;;
      q|Q) break ;;
      *) echo "Geçersiz seçim." ;;
    esac
    echo
  done
}

# Komut adı: help_ipban
help_ipban() { help_menu; }

# Doğrudan çağrılırsa menüyü aç
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  require_root
  help_menu
fi
HB

  sudo chmod +x "${HELP_BIN}"
}

# ------------------------------------------------------------
# Ana Akış
# ------------------------------------------------------------
main() {
  read_user_input
  setup_fail2ban
  setup_python_script
  setup_systemd
  install_help_menu

  log_info "------------------------------------------------------------"
  log_info "${GREEN}Kurulum Başarılı!${NC}"
  log_info "Raporlama her ${REPORT_PERIOD_MIN} dakikada bir otomatik çalışacaktır."
  log_info "Manuel test çalıştırması için: sudo systemctl start ssh-telegram-alert.service"
  log_info "Fail2Ban durumu: sudo systemctl status fail2ban"
  log_info "Raporlama durumu: sudo systemctl status ssh-telegram-alert.timer"
  # Yardım menüsü komutu
  log_info "Yardım/Ayar menüsünü açmak için: ${YELLOW}sudo help_ipban${NC}"
  log_info "------------------------------------------------------------"
}

main
