import ast
import json
import os
import random
import sqlite3
import string
from datetime import datetime, timedelta

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
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
from sqlalchemy import or_
from flask_login import current_user
from flask import request, render_template

app = Flask(__name__)
app.secret_key = "supersecretkey"
APP_TOKEN = "yandexlyceum_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config['STATIC_FOLDER'] = './static'

UPLOAD_FOLDER = 'static/img/up'
UPLOAD_FOLDER_COVERS = 'uploads/covers'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['UPLOAD_FOLDER_COVERS'] = UPLOAD_FOLDER_COVERS
covers = app.config['UPLOAD_FOLDER_COVERS']

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


INVITE_SYSTEM = True

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
ADMINS = 5
SYS = 100

app.config.update(
    MAIL_SERVER='smtp.mail.ru',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USERNAME = 'support@clsr.ru',
    MAIL_PASSWORD = 'c5OdLAtnzro4hFzNQsP9'
)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)


def downoload_users_datum(user_id, flag=True):
    con = sqlite3.connect('instance/users.db')
    cur = con.cursor()
    # Выполняем основной запрос к таблице users
    if flag:
        user_data = cur.execute('SELECT id, email, rank, verified FROM user WHERE id=?', (user_id,)).fetchone()
    else:
        user_data = cur.execute('SELECT id, name FROM user WHERE id=?', (user_id,)).fetchone()
    return user_data


def get_data(data, path, default=None, separator='/'):
    global dict_data
    try:
        dict_data = ast.literal_eval(data)
    except Exception as e:
        print("Ошибка преобразования:", e)

    keys = path.split(separator)
    current = dict_data

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

    return current[last_key], current

#=========================ДИСКОРД=========================
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

#=========================МОДЕЛИ ДБ=========================
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
        db.session.commit()

    def set_hwid(self, hwid):
        self.hwid = hwid

    def check_password(self, password_input):
        return check_password_hash(self.password, password_input)


class Post(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=True)
    content = db.Column(db.String, nullable=True)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_private = db.Column(db.Boolean, default=True)
    tag = db.Column(db.String, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship('User')


class Comment(db.Model, UserMixin):
    __tablename__ = 'com'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    post_id = db.Column(db.Integer)
    content = db.Column(db.String, nullable=True)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship('User')

    parent_id = db.Column(db.Integer, db.ForeignKey('com.id'), nullable=True)
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy='dynamic')


class Invite(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    code = db.Column(db.String, nullable=False, unique=True)
    rank = db.Column(db.Integer, default=0)
    sender_id = db.Column(db.Integer)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship('User')


def create_invite(code, sender_id=0, rank=0):
    try:
        invobj = Invite.query.filter_by(code=code).first()
        if invobj:
            error = 'Уже есть такой инвайт!'
            raise Exception(error)
        invite = Invite(code=code, sender_id=sender_id, rank=rank)
        db.session.add(invite)
        db.session.commit()
        return 'Успех!'
    except Exception as e:
        return str(e)


def delete_old_unused_invites(days=31, force=False):
    try:
        time_threshold = datetime.utcnow() - timedelta(days=days)
        if force:
            time_threshold = datetime.utcnow()
        Invite.query.filter(
            Invite.receiver_id.is_(None)
        ).all()
        query = Invite.query.filter(
            Invite.receiver_id.is_(None),
            Invite.created_date < time_threshold
        )
        query.count()
        query.delete(synchronize_session=False)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Ошибка при удалении: {str(e)}")
        raise e


#=========================ХЕНДЛЕРЫ=========================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized_callback():
    return render_template('404.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


#=========================АВТОРИЗАЦИЯ=========================
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']
        if INVITE_SYSTEM:
            invite_code = request.form['invite']
        else:
            invite_code = 'sys' + str(User.query.count() + 1)
            create_invite(invite_code)
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
            inviter = User.query.filter_by(id=invite.sender_id).first()
            cdata = get_data(inviter.data, 'invites_list', default=[])
            if cdata[0]:
                cdata[1]['invites_list'].remove(invite_code)
                inviter.data = str(cdata[1])
                db.session.commit()

            hashed_password = generate_password_hash(password)
            new_user = User(email=email, name=email.split("@")[0], password=hashed_password, rank=invite.rank, data=json.dumps({}))
            db.session.add(new_user)
            db.session.commit()
            user = User.query.filter_by(email=email).first()
            invite.receiver_id = user.id
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html', error=error, inv=INVITE_SYSTEM)

@app.route('/invite', methods=['GET', 'POST'])
@login_required
def invite():
    if current_user.rank < SYS :
        return render_template('404.html')
    error = None
    if request.method == 'POST':
        code = request.form['code']
        if request.form['rank'] == '': rank = 0
        else: rank = int(request.form['rank'])
        try:
            if current_user.rank != SYS and rank >= ADMINS or code[:3] == 'sys':
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

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        token = serializer.dumps(email, salt='password-reset-salt-baby')
        reset_url = url_for('reset_password', token=token, _external=True)

        flash('Письмо с инструкциями отправлено на почту.', 'info')
        user = User.query.filter_by(email=email).first()
        # Отправляем письмо
        if user:
            msg = Message(
                subject='Сброс пароля',
                sender='support@clsr.ru',
                recipients=[email]
            )
            msg.body = f'Чтобы сбросить пароль, перейдите по ссылке: {reset_url}'
            mail.send(msg)

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    error = None
    try:
        email = serializer.loads(token, salt='password-reset-salt-baby', max_age=600)
    except SignatureExpired:
        return 'Ссылка устарела.'
    except BadSignature:
        return 'Недействительная ссылка.'

    if request.method == 'POST':
        new_password = request.form['password']
        new_passwordс = request.form['passwordс']
        if new_password != new_passwordс:
            return render_template('reset_password.html', error="Пароли не совпадают")
        user = User.query.filter_by(email=email).first()
        user.set_password(new_password)
        print('Установлен новый пароль для', email)
        return 'Пароль был успешно обновлён.'

    return render_template('reset_password.html', error=error)


#=========================ПОЛЬЗОВАТЕЛЬ=========================
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
    error = None
    success = None
    if request.method == 'POST':
        if request.form.get('name'):
            user.name = request.form.get('name')
            success = 'Успех'
        if request.form.get('password'):
            if current_user.check_password(request.form.get('password')):
                if request.form.get('password_new') == request.form.get('password_new_confirm'):
                    user.set_password(request.form.get('password_new'))
                    success = 'Успех'
                else:
                    error = 'Пароли не совпадают'
            else:
                error = 'Неверный пароль'
        db.session.commit()
    return render_template('settings.html', error=error, success=success)

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


#=========================БАЗА=========================
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

def generate_random_invite(uid, length=36):
    while True:
        characters = string.ascii_letters + string.digits
        inv = ''.join(random.choice(characters) for _ in range(length))
        if not Invite.query.filter_by(code=inv).first():
            create_invite(inv, uid)
            return inv

@app.route('/invites', methods=['GET', 'POST'])
def invites():
    delete_old_unused_invites()
    global cdata, time_threshold
    user = User.query.filter_by(id=current_user.id).first()
    data = user.data
    try:
        cdata = get_data(data, 'invites', default="None")
        if cdata[0] == "None":
            cdata[1]['invites'] = 1
            cdata[1]['invites_list'] = []
            user.data = str(cdata[1])
            db.session.commit()
    except Exception as e:
        print(e)
    invites = int(cdata[1]['invites'])
    for i in range(invites):
        inv = generate_random_invite(user.id)
        cdata[1]['invites_list'].append(inv)
        cdata[1]['invites'] = int(cdata[1]['invites']) - 1

    for inv in cdata[1]['invites_list']:
        if not Invite.query.filter_by(code=inv).first():
            cdata[1]['invites_list'].remove(inv)

    try:
        inv = Invite.query.filter_by(
            sender_id=current_user.id,
            receiver_id=None
        ).order_by(
            Invite.created_date.asc()  # Сортируем по дате создания (от старых к новым)
        ).first().created_date
    except Exception as e:
        inv = False
    if inv:
        time_threshold = (inv + timedelta(days=31)).strftime('%Y-%m-%d %H:%M:%S')
    else:
        time_threshold = 'никогда'

    user.data = str(cdata[1])
    db.session.commit()
    return render_template('giveinvites.html', time_threshold=time_threshold, invlist=cdata[1]['invites_list'])


#=========================ФОРУМ=========================
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

@app.route('/forum/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def post_detail(post_id):
    post = Post.query.filter(Post.id == post_id).first()
    if '#private' in post.content.split('\n')[0]:
        line = (post.content.split('\n')[0]).strip().split()
        line.remove('#private')
        if str(current_user.id) not in line and current_user.rank < ADMINS:
            return "Доступа нет"
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
    return render_template('forum_detail4.html', post=post, comments=comments, admins=ADMINS, Comment=Comment, reply_to=reply_to,  datetime=datetime)

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
        if not "(edited)" in request.form['title']:
            news.title = request.form['title'] + " (edited)"
        news.content = request.form['content']
        db.session.commit()
        return redirect(url_for('forum'))

    # Отображение формы редактирования
    return render_template('forum_edit.html', post=news)


#=========================DISCORD=========================
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


#=========================RCON МАЙНКРАФТ=========================
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


#=========================API=========================
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


#=========================ЗАПУСК=========================
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)