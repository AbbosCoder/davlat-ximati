from app import app, db, AdminUser
with app.app_context():
    admin = AdminUser(username='admin')
    admin.set_password('admin')  # o'zingiz xohlagan parolni yozing
    db.session.add(admin)
    db.session.commit()