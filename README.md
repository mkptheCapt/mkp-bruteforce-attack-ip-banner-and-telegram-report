# mkp-bruteforce-attack-ip-banner-and-telegram-report
That detects bruteforce attacks and bans their ip  and send you logs-reports regularly via telegram bot

Kurulum Rehberi
Yeni VPS'inizde kurulumu yapmak için gerekli komutları ve süreci aşağıda bulabilirsiniz. Bu işlem, depoyu klonlamayı ve ardından interaktif kurulum betiğini çalıştırmayı içerir.
Tek Komutla Yeni VPS'te Kurulum Süreci
Yeni Ubuntu VPS'inizde, tüm kurulumu gerçekleştirmek için aşağıdaki adımları sırasıyla uygulayın:
Adım 1: Git Kurulumu (Gerekliyse)
Yeni VPS'inizde Git'in kurulu olduğundan emin olun.

sudo apt update

sonra bu komutu girin:

sudo apt install git -y

Adım 2: Depoyu Klonlama
Deponuzu VPS'e indirmek için aşağıdaki komutu kullanın. Bu komut, bulunduğunuz dizine mkp-bruteforce-attack-ip-banner-and-telegram-report adında bir klasör oluşturacaktır.


git clone https://github.com/mkptheCapt/mkp-bruteforce-attack-ip-banner-and-telegram-report.git


Adım 3: Klasöre Geçme
Oluşturulan klasörün içine gidin.

cd mkp-bruteforce-attack-ip-banner-and-telegram-report

Adım 4: Kurulum Betiğini Çalıştırma
Şimdi, önceki adımda hazırladığımız ve sizden Telegram Bot Token ve Chat ID isteyen interaktif betiği çalıştırın.

sudo bash install_ssh_alert.sh

Betik Çalıştırıldığında Ne Olacak?
 * Betiği çalıştırdıktan sonra sizden sırasıyla Telegram Bot Token ve Telegram Chat ID istenir.
 * Betiğin geri kalanı, tüm kurulumu otomatik olarak tamamlar:
   * Fail2Ban yüklenir ve ayarlanır (maxretry=6, bantime=2400h).
   * Python betiği (ssh_alert.py) /etc/ssh-alert/ altına kopyalanır.
   * Girdiğiniz Telegram bilgileri /etc/ssh-alert/config.json dosyasına yazılır.
   * Systemd servisleri ve Timer ayarlanır (60 dakikada bir raporlama için).
   * Tüm servisler başlatılır.
Kurulum tamamlandığında, betik size $Kurulum Başarılı!$ mesajını gösterecektir.
Artık yeni VPS'inizde de aynı güçlü güvenlik ve raporlama sistemine sahipsiniz!

Telegram Raporlama örnek ekranı:
[imglhttps://i.ibb.co/PsDVHWmq/image.png[/img]
