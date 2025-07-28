import random

from aapp import app, delete_old_unused_invites, User, db, get_data

# Создаем контекст приложения
with app.app_context():
    # Теперь внутри контекста можно работать с БД
    delete_old_unused_invites(force=True)

    allu = User.query.count()
    print(f"Всего пользователей: {allu}")

    for user in User.query.all():
        cdata = get_data(user.data, 'invites')
        if cdata and user.id < allu/3 + 3 and user.verified and user.rank >= 1:
            cdata[1]['invites'] = random.randint(0, 2)
            user.data = str(cdata[1])
        elif cdata:
            cdata[1]['invites'] = 0
            user.data = str(cdata[1])
        if (user.id // allu) % 10:
            print(user.id // allu * 100, "%")
        db.session.commit()