import ast
import json


def get_or_create_nested(data, path, default=None, separator='/'):
    keys = path.split(separator)
    current = data

    # Проходим по всем ключам кроме последнего
    for key in keys[:-1]:
        # Если ключ отсутствует или не является словарем - создаем новый словарь
        if key not in current or not isinstance(current.get(key), dict):
            current[key] = {}
        current = current[key]

    # Работаем с последним ключом
    last_key = keys[-1]
    if last_key not in current:
        current[last_key] = default

    return current[last_key]


data = {
    "user": {
        "name": "Alice",
        "address": {
            "city": "Wonderland",
        }
    }
}

# Тестируем запросы
print(get_or_create_nested(data, "user/address/zip", 10000))  # 10000
print(data["user"]["address"]["zip"])  # 10000

# 4. Попытка перезаписать существующие данные
print(get_or_create_nested(data, "user/name", "Bob"))  # "Alice" (не изменилось)
print(data["user"]["name"])  # "Alice"
