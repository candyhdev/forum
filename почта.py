import smtplib
from email.mime.text import MIMEText

# ==== КОНФИГУРАЦИЯ ====
SMTP_SERVER = 'smtp.mail.ru'          # или smtp.yandex.ru, если используешь Яндекс
SMTP_PORT = 587
USERNAME = 'support@clsr.ru'          # твой email
PASSWORD = 'c5OdLAtnzro4hFzNQsP9'       # здесь должен быть SMTP-пароль, не обычный

TO_EMAIL = 'candyvar@mail.ru'           # получатель тестового письма

# ==== СОДЕРЖИМОЕ ПИСЬМА ====
subject = 'Тест SMTP'
body = 'Если ты это читаешь — SMTP работает ✅'

msg = MIMEText(body)
msg['Subject'] = subject
msg['From'] = USERNAME
msg['To'] = TO_EMAIL

# ==== ОТПРАВКА ====
try:
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(USERNAME, PASSWORD)
    server.send_message(msg)
    server.quit()
    print('✅ Письмо отправлено успешно!')
except smtplib.SMTPAuthenticationError as e:
    print('❌ Ошибка авторизации:')
    print(e.smtp_error.decode())
except Exception as e:
    print('❌ Другая ошибка:')
    print(e)
