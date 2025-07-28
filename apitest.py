import ast
from datetime import datetime

import requests
import json

from crypto import encrypt, decrypt

# URL локального сервера
url = "http://127.0.0.1:5000/sc"

# Данные для отправки
test = {
    "email": encrypt("candyvar@mail.ru"),
    "password": encrypt("1"),
    "date": datetime.utcnow().isoformat(),
}

# Заголовки запроса
headers = {
    "Authorization": encrypt("Bearer yandexlyceum_secret_key"),
    "TSC": encrypt("auth-login")
}

# Данные запроса (зашифрованный JSON)
payload = {
    "SC": encrypt(json.dumps(test))  # Преобразуем в JSON перед шифрованием
}

# Отправка POST-запроса
response = requests.post(url, json=payload, headers=headers)

# Обработка ответа
if response.status_code == 200:
    # Расшифровка данных
    response_data = response.json()
    data = decrypt(response_data.get("SC"))
    gone_data = ast.literal_eval(data)

    print("✅ Расшифрованный ответ:", gone_data)
else:
    print("❌ Ошибка:", response.status_code, response.text)


a = response_data.get("SC")
b = "nBes8YaaQVSTdwWraBuS/kW2xdPh8Pwwnpjx0CL5bd/98hX1iUO6nacSAfRTbs0KLbGevM9tLZGt3ToN8N0oMeU0XSpRKosC8AC4lnxiF3W7qzmAnKMpxs+QVYmYBXf/0YRiZ1rI4EUfrbMv37fpPGoD460KndFp6bkGgbxWurw="

from Levenshtein import ratio
similarity_score = ratio(a, b)
print(similarity_score)  # Ответ: "0.57142". Достаточно высокая схожесть, несмотря на различия в словах!