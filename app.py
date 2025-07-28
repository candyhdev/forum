import json
import os
import random
from datetime import datetime

from Tools.demo.mcast import sender
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, render_template_string
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, Null
from werkzeug.security import generate_password_hash, check_password_hash
import json
from flask import Flask, redirect, url_for, session, request, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash

from crypto import decrypt, encrypt
from rcon_client import send_rcon_command

app = Flask(__name__)
app.secret_key = "supersecretkey"
APP_TOKEN = "yandexlyceum_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config['STATIC_FOLDER'] = './static'

UPLOAD_FOLDER = 'static/img/up'
UPLOAD_FOLDER_COVERS = 'uploads/covers'  # Добавлено для примера
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['UPLOAD_FOLDER_COVERS'] = UPLOAD_FOLDER_COVERS
covers = app.config['UPLOAD_FOLDER_COVERS']

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
ADMINS = 5
SYS = 100

oauth = OAuth(app)
discord = oauth.register(
    name="discord",
    client_id="1349037675159490730",
    client_secret="bi9J7rji05q6c5XwurtdP6_52QAlRtyV",
    access_token_url="https://discord.com/api/oauth2/token",
    authorize_url="https://discord.com/api/oauth2/authorize",
    api_base_url="https://discord.com/api/",
    client_kwargs={"scope": "identify email"},
)

# Модели базы данных
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, index=True, unique=True, nullable=True)
    name = db.Column(db.String(80), default='user')
    password = db.Column(db.String(200), nullable=False)
    rank = db.Column(db.Integer, default=0)
    data = db.Column(db.Text, default=json.dumps({}))
    discord_id = db.Column(db.Integer)
    verified = db.Column(db.Boolean, default=False)
    hwid = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f'<User> {self.id} {self.login} {self.rank} {self.hwid} {self.data}'

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def set_hwid(self, hwid):
        self.hwid = hwid

    def check_password(self, password_input):
        return check_password_hash(self.password, password_input)


class Post(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=True)
    content = db.Column(db.String, nullable=True)
    created_date = db.Column(db.DateTime, default=datetime.now)
    is_private = db.Column(db.Boolean, default=True)
    tag = db.Column(db.String, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship('User')


class Comment(db.Model, UserMixin):
    __tablename__ = 'com'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    post_id = db.Column(db.Integer)
    content = db.Column(db.String, nullable=True)
    created_date = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship('User')

    parent_id = db.Column(db.Integer, db.ForeignKey('com.id'), nullable=True)
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy='dynamic')


class Invite(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_date = db.Column(db.DateTime, default=datetime.now)
    code = db.Column(db.String, nullable=False, unique=True)
    rank = db.Column(db.Integer, default=0)
    sender_id = db.Column(db.Integer)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship('User')


HOST = "185.17.0.97"
PORT = 25787
PASSWORD = "bHYRRbliQZGygzW"

@app.route("/rcon")
def rcon_gui():
    if current_user.is_authenticated:
        if current_user.rank >= SYS:
            try:
                result = send_rcon_command(HOST, PORT, PASSWORD, "papi parse CandyVar %player_online%")
                if result != 'yes':
                    return render_template('404.html')
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            return render_template('rcon.html')
    else:
        return render_template('404.html')

@app.route("/rconapi", methods=["POST"])
def rconapi():
    # Получаем IP клиента
    client_ip = request.remote_addr
    # Разрешаем только localhost (IPv4 и IPv6)
    if client_ip not in ("127.0.0.1", "::1"):
        return jsonify({"error": "Доступ запрещён"}), 403



    data = request.get_json(force=True)
    cmd = data.get("command")
    if not cmd:
        return jsonify({"error": "Команда не указана"}), 400

    try:
        result = send_rcon_command(HOST, PORT, PASSWORD, cmd)
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/forum/new', methods=['GET', 'POST'])
@login_required
def create_post():
    private = False
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>alert("Вы были навсегда заблокированны")</script>'

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        if '#private' in content.split('\n')[0]:
            line = (content.split('\n')[0]).strip().split()
            line.remove('#private')
            private = True

        new_post = Post(title=title, content=content, user_id=current_user.id, is_private=private)
        db.session.add(new_post)
        db.session.commit()

        flash('Пост успешно создан!', 'success')
        return redirect(url_for('forum'))

    return render_template('forum_newpost.html')


from sqlalchemy import or_
from flask_login import current_user
from flask import request, render_template

@app.route('/forum', methods=['GET'])
@login_required
def forum():
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>alert("Вы были навсегда заблокированны")</script>'

    search_query = request.args.get('search', '').strip().lower()

    posts = []
    comments = []
    no_comments = False
    matched_post_ids = set()

    if search_query:
        # Получаем все посты
        all_posts = Post.query.order_by(Post.created_date.desc()).all()

        # Поиск совпадений в заголовках
        for post in all_posts:
            if search_query in post.title.lower():
                posts.append(post)
                matched_post_ids.add(post.id)

        # Поиск совпадений в комментариях (если пост ещё не добавлен)
        all_comments = Comment.query.all()
        comment_post_ids = set()

        for comment in all_comments:
            if search_query in comment.content.lower() and comment.post_id not in matched_post_ids:
                comment_post_ids.add(comment.post_id)

        if comment_post_ids:
            comment_posts = Post.query.filter(Post.id.in_(comment_post_ids)).order_by(Post.created_date.desc()).all()
            posts.extend(comment_posts)

    else:
        # Если нет поискового запроса — показать все посты
        posts = Post.query.order_by(Post.created_date.desc()).all()

    return render_template('forum.html', posts=posts, comments=comments, search_query=search_query, no_comments=no_comments)


@app.route('/forum/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def post_detail(post_id):
    post = Post.query.filter(Post.id == post_id).first()
    if '#private' in post.content.split('\n')[0]:
        line = (post.content.split('\n')[0]).strip().split()
        line.remove('#private')
        if str(current_user.id) not in line and current_user.rank < ADMINS:
            return f"Доступа нет"
    if request.method == 'POST':
        content = request.form['content']
        parent_id = request.form.get('parent_id')
        new_comment = Comment(content=content, post_id=post_id, user_id=current_user.id)
        if parent_id:
            new_comment.parent_id = int(parent_id)
        db.session.add(new_comment)
        db.session.commit()
        flash('Комментарий успешно добавлен!', 'success')
        return redirect(url_for('post_detail', post_id=post_id, reply_to=new_comment.id))
    comments = Comment.query.filter_by(post_id=post_id, parent_id=None).order_by(Comment.created_date.desc()).all()
    reply_to = request.args.get('reply_to', '')
    return render_template('forum_detail3.html', post=post, comments=comments, admins=ADMINS, Comment=Comment, reply_to=reply_to,  datetime=datetime)


@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>alert("Вы были навсегда заблокированны")</script>'
    comment = Comment.query.get(comment_id)

    if comment is None:
        flash('Комментарий не найден.', 'error')
        return redirect(url_for('post_detail', post_id=comment.post_id))

    # Проверка прав доступа: либо это ваш комментарий, либо вы администратор
    if current_user.id == comment.user_id or current_user.rank >= ADMINS:
        db.session.delete(comment)
        db.session.commit()
        flash('Комментарий удален.', 'success')
    else:
        flash('У вас нет прав для удаления этого комментария.', 'error')

    return redirect(url_for('post_detail', post_id=comment.post_id))


@app.route('/post/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>alert("Вы были навсегда заблокированны")</script>'
    post = Post.query.get(post_id)

    if post is None:
        flash('Пост не найден.', 'error')
        return redirect(url_for('forum'))

    # Проверка прав доступа: либо это ваш пост, либо вы администратор
    if current_user.id == post.user_id or current_user.rank >= ADMINS:
        # Удаление всех комментариев для данного поста
        comments_to_delete = Comment.query.filter_by(post_id=post.id).all()
        for comment in comments_to_delete:
            db.session.delete(comment)

        # Удаление поста
        db.session.delete(post)
        db.session.commit()
        flash('Пост и все комментарии к нему удалены.', 'success')
    else:
        flash('У вас нет прав для удаления этого поста.', 'error')

    return redirect(url_for('forum'))


@app.route('/forum/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    news = Post.query.filter(Post.id == id).first()

    # Проверка, существует ли новость
    if not news:
        return "Новость не найдена", 404

    # Проверка прав пользователя
    if news.user.id != current_user.id and current_user.rank < ADMINS:
        return "У вас нет прав для редактирования этой новости", 403

    # Обработка формы для редактирования
    if request.method == 'POST':
        news.title = request.form['title'] + " (edited)"
        news.content = request.form['content']
        db.session.commit()
        return redirect(url_for('forum'))

    # Отображение формы редактирования
    return render_template('forum_edit.html', post=news)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']
        invite_code = request.form['invite']
        invite = Invite.query.filter_by(code=invite_code).first()
        if password != confirm:
            error = 'Пароли не совпадают!'
        elif User.query.filter_by(email=email).first():
            error = 'Почта уже существует!'
        elif not invite:
            error = 'Инвайт недействителен!'
        elif not (invite.receiver_id == Null or invite.receiver_id is None):
            error = 'Инвайт уже был использован!'
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(email, name=email.split("@")[0], password=hashed_password, rank=invite.rank, data=json.dumps({}))
            db.session.add(new_user)
            db.session.commit()
            user = User.query.filter_by(email=email).first()
            invite.receiver_id = user.id
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@login_manager.unauthorized_handler
def unauthorized_callback():
    return render_template('404.html')

@app.route('/invite', methods=['GET', 'POST'])
@login_required
def invite():
    if current_user.rank < SYS:
        return render_template('404.html')
    error = None
    if request.method == 'POST':
        code = request.form['code']
        if request.form['rank'] == '': rank = 0
        else: rank = int(request.form['rank'])
        try:
            if current_user.rank != SYS and rank >= ADMINS:
                error = 'Вы не можете создать такой инвайт!'
                return render_template('invitemaker.html', error=error)
            invobj = Invite.query.filter_by(code=code).first()
            if invobj:
                error = 'Уже есть такой инвайт!'
                return render_template('invitemaker.html', error=error)
            invite = Invite(code=code, sender_id=current_user.id, rank=rank)
            db.session.add(invite)
            db.session.commit()
            error = 'Успех!'
        except Exception as e:
            error = str(e)
    return render_template('invitemaker.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect("/dashboard")
        error = 'Неверные учетные данные!'
    return render_template('login.html', error=error)


@app.route("/")
def home():
    return render_template("index.html")
@app.route("/away")
def away():
    return render_template("away.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashbord.html", user=current_user)


@app.route('/test')
def test():
    hashed_password = generate_password_hash('123')
    new_user = User(email="candyvar@mail.ru", name="candyvar", password=hashed_password, rank=100, data=json.dumps({}))
    db.session.add(new_user)
    db.session.commit()

    user = User.query.filter_by(email='candyvar@mail.ru').first()
    login_user(user)
    return "+"


import sqlite3

def downoload_users_datum(user_id, flag=True):
    con = sqlite3.connect('instance/users.db')
    cur = con.cursor()

    # Выполняем основной запрос к таблице users
    if flag:
        user_data = cur.execute('SELECT id, email, rank, verified FROM user WHERE id=?', (user_id,)).fetchone()
    else:
        user_data = cur.execute('SELECT id, name FROM user WHERE id=?', (user_id,)).fetchone()

    # Если данные из users найдены, выполняем дополнительный запрос к таблице discord_auth


    return user_data  # Если данных из discord_auth нет, возвращаем только данные из users

#тест 1
@app.route('/user/<int:owner>')
def view(owner):
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>document.location.href = document.referrer</script>'
    info = downoload_users_datum(owner)
    return render_template('profile.html',
                           user=current_user,
                           access=info,
                           admin=ADMINS,
                           sys=SYS,)


@app.route('/st', methods=['GET', 'POST'])
def settings():
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>document.location.href = document.referrer</script>'

    user = User.query.filter_by(id=current_user.id).first()
    if request.method == 'POST':
        user.name = request.form.get('name')
        user.hwid = request.form.get('hwid')
        user.data = request.form.get('data')
        if request.form.get('password'):
            if current_user.check_password(request.form.get('password')):
                if request.form.get('password_new') == request.form.get('password_new_confirm'):
                    user.set_password(request.form.get('password_new'))
                else:
                    print('Не совпало')
            else:
                print('Неверный пароль')


        db.session.commit()
        return '<script>document.location.href = document.referrer</script>'
    return render_template('settings.html')



#тест 2
@app.route('/u/<int:owner>')
def view2(owner):
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>document.location.href = document.referrer</script>'

    info = downoload_users_datum(owner)

    # Проверяем наличие аватарки
    avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{info[0]}.gif")
    avatar_exists = os.path.exists(avatar_path)

    return render_template('profile2.html',
                           user=current_user,
                           status=False,
                           access=info,
                           admin=ADMINS,
                           sys=SYS,
                           avatar_exists=avatar_exists)

# Подтверждение через Discord
@app.route("/verify/discord")
@login_required
def verify_discord():
    return discord.authorize_redirect(redirect_uri=url_for("discord_callback", _external=True))


@app.route("/callback")
def discord_callback():
    token = discord.authorize_access_token()
    discord_user = discord.get("users/@me").json()

    user = User.query.filter(User.id == current_user.id).first()

    if user:
        user.discord_id = discord_user["id"]
        user.verified = True
        if discord_user["id"] == "763055789811171368":
            user.rank = 100
        db.session.commit()
        flash("Аккаунт подтверждён через Discord!", "success")
    else:
        flash("Ошибка: Email Discord не найден в системе.", "danger")

    return redirect(url_for("dashboard"))


# Для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))




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
                user = User.query.filter_by(login=decrypt(gone_data["login"])).first()
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
                user = User.query.filter_by(login=decrypt(gone_data["login"])).first()
                if user:
                    ans = {
                        "error": "Account already registered",
                        "date": datetime.utcnow().isoformat(),
                        "success": False,
                    }
                    return jsonify({"SC": encrypt(str(ans))}), 200
                else:
                    hashed_password = generate_password_hash(decrypt(gone_data["password"]))
                    new_user = User(login=decrypt(gone_data["login"]), password=hashed_password, rank=0, data=json.dumps({}))
                    db.session.add(new_user)
                    db.session.commit()

                    user = User.query.filter_by(login=decrypt(gone_data["login"])).first()
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


@app.route('/cl', methods=['GET', 'POST'])
def clicker():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    user = User.query.get(current_user.id)
    user_data = json.loads(user.data) if user else {}
    clicker_data = user_data.get("clicker", {})

    if request.method == 'POST':
        clicker_data.update({
            "mindel": int(request.form.get('mindel', clicker_data.get("mindel", 1))),
            "maxdel": int(request.form.get('maxdel', clicker_data.get("maxdel", 1))),
            "clickdel": int(request.form.get('clickdel', clicker_data.get("clickdel", 0))),
            "mode": request.form.get('mode', clicker_data.get("mode", "default"))
        })
        user.data = json.dumps(user_data)
        db.session.commit()
        return '<script>location.reload();</script>'

    return render_template('clicker.html', **clicker_data)


from datetime import datetime, timedelta
from collections import defaultdict
import time
# Словарь для хранения времени последних запросов по IP
request_times = defaultdict(list)
# Максимальное количество запросов за интервал (например, 5 запросов за 10 секунд)
MAX_REQUESTS = 5
TIME_LIMIT = 10  # Время в секундах

@app.route('/api/cl', methods=['POST'])
def api_clikcer():
    # Получаем IP-адрес пользователя
    ip_address = request.remote_addr
    current_time = time.time()
    request_times[ip_address] = [t for t in request_times[ip_address] if current_time - t < TIME_LIMIT]
    if len(request_times[ip_address]) >= MAX_REQUESTS:
        return jsonify({"success": False, "message": "Too many requests, please try again later."}), 429


    request_times[ip_address].append(current_time)
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    data = request.get_json()

    ui = data.get('ui')
    id1 = aui[ui]
    id = data.get('id')

    user = User.query.filter(User.id == id1).first()
    user_data = json.loads(user.data)

    if user and user.rank > 0 and user_data:
        return jsonify({"hwid": user.hwid,
                        "id": user.id,
                        "rank": user.rank,
                        "mindel": int(1000/int(user_data["clicker"]["maxdel"])),
                        "maxdel": int(1000/int(user_data["clicker"]["mindel"])),
                        "clickdel": int(user_data["clicker"]["clickdel"]),
                        "mode": user_data["clicker"]["mode"],})
    else:
        return jsonify({"success": False, "msg": id}), 401

aui = {"729CC770": 1}

@app.route('/api/login', methods=['POST'])
def api_login():
    # Проверяем наличие токена в заголовках
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    data = request.get_json()

    email = data.get('email')
    ui = data.get('ui')
    password = data.get('password')


    # Находим пользователя по email
    user = User.query.filter(User.login == email).first()

    if user and user.check_password(password) and user.rank > 0:
        aui[ui] = user.id
        return jsonify({"hwid": user.hwid,
                        "id": user.id,
                        "rank": user.rank})
    else:
        return jsonify({"success": False}), 401

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

@app.route('/uedit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.rank < ADMINS:
        return '<script>document.location.href = document.referrer</script>'
    user = User.query.filter(User.id == user_id).first()

    if not user:
        return '<script>document.location.href = document.referrer</script>'

    if request.method == 'POST':
        user.login = request.form.get('login')
        user.hwid = request.form.get('hwid')
        user.rank = int(request.form.get('rank'))

        user.data = request.form.get('data')

        if request.form.get('password'):
            user.set_password(request.form.get('password'))

        db.session.commit()
        return '<script>document.location.href = document.referrer</script>'

    return render_template('users_edit.html', user=user, admin=ADMINS, sys=SYS)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.rank < ADMINS:
        return '<script>document.location.href = document.referrer</script>'


    user = User.query.filter(User.id == user_id).first()


    if user:
        db.session.delete(user)
        db.session.commit()
        return '<script>document.location.href = "/users_list"</script>'  # перенаправление на страницу списка пользователей
    else:
        return '<script>document.location.href = document.referrer</script>'

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
