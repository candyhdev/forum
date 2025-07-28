from aapp import *


@app.route("/sc", methods=['GET', 'POST'])
def securechennal():
    #print("RAW DATA:", request.data)  # Логируем полученные данные
    try:
        token = decrypt(request.headers.get('Authorization'))
        tsc = decrypt(request.headers.get('TSC'))

        if token != f"Bearer {APP_TOKEN}":
            return jsonify({"success": False, "message": "Unauthorized"}), 403

        request_data = request.get_json()
        data = decrypt(request_data.get("SC"))
        data = data.replace("'", "\"")
        gone_data = json.loads(data)

        if request_data is None:
            return jsonify({"error": "00"}), 400
        elif not tsc:
            return jsonify({"error": "01"}), 400
        elif not data:
            return jsonify({"error": "02"}), 400

        match tsc:
            case "auth-login":
                user = User.query.filter_by(email=decrypt(gone_data["email"])).first()
                if not user.check_password(decrypt(gone_data["password"])):
                    ans = {
                        "date": datetime.utcnow().isoformat(),
                        "success": False,
                    }
                    return jsonify({"SC": encrypt(str(ans))}), 200
                else:
                    ans = {
                        "id": user.id,
                        "rank": user.rank,
                        "data": user.data,
                        "verified": user.verified,
                        "date": datetime.utcnow().isoformat(),
                        "success": True,
                    }
                    return jsonify({"SC": encrypt(str(ans))}), 200
            case "auth-register":
                user = User.query.filter_by(email=decrypt(gone_data["email"])).first()
                if user:
                    ans = {
                        "error": "Account already registered",
                        "date": datetime.utcnow().isoformat(),
                        "success": False,
                    }
                    return jsonify({"SC": encrypt(str(ans))}), 200
                else:
                    hashed_password = generate_password_hash(decrypt(gone_data["password"]))
                    new_user = User(email=decrypt(gone_data["email"]), password=hashed_password, rank=0, data=json.dumps({}))
                    db.session.add(new_user)
                    db.session.commit()

                    user = User.query.filter_by(email=decrypt(gone_data["email"])).first()
                    ans = {
                        "id": user.id,
                        "rank": user.rank,
                        "data": user.data,
                        "verified": user.verified,
                        "date": datetime.utcnow().isoformat(),
                        "success": True,
                    }
                    return jsonify({"SC": encrypt(str(ans))}), 200


            case "restart":
                print("Перезапуск программы...")
            case _:  # Аналог default в switch-case
                print("Неизвестная команда!")

        print(request_data)
        print(data)

        return jsonify({"data": encrypt("decrypted")}), 200
    except Exception as e:
        print("Ошибка:", e)
        return jsonify({"error": "?"}), 500


@app.route('/api/sethwid', methods=['POST'])
def set_hwid():
    data = request.get_json()

    # Проверяем наличие токена в заголовках
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    email = data.get('email')
    hwid = data.get('hwid')
    password = data.get('password')  # Добавляем поле для пароля

    # Создаем сессию для работы с БД

    # Находим пользователя по email
    user = User.query.filter(User.login == email).first()

    if user:
        # Проверяем правильность пароля
        if user.check_password(password):
            if user.hwid is None or user.hwid == "None":
                user.set_hwid(hwid)
                db.session.commit()
                return jsonify({"success": True, "message": "HWID updated"})
            else:
                return jsonify({"success": False, "message": "HWID already set"}), 400
        else:
            return jsonify({"success": False, "message": "Invalid password"}), 401
    else:
        return jsonify({"success": False, "message": "User not found"}), 404

a = {
    "clicker": {
        "mindel": 0,
        "maxdel": 0,
        "clickdel": 0,
        "mode": "legit"
    }
}