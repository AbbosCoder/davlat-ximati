from flask import Flask, render_template, request, redirect, url_for, flash, make_response, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from datetime import datetime
from random import randint
from xhtml2pdf import pisa
from io import BytesIO
from flask_admin import AdminIndexView
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'secret123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100))
    passport_number = db.Column(db.String(50))
    phone_number = db.Column(db.String(20))
    service_type = db.Column(db.String(100))
    service_number = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Admin panel

# Admin user model
class AdminUser(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(120))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Secure ModelView
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

# Secure AdminIndexView
class SecureAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))

# Admin panel setup
admin = Admin(app, name='Davlat Xizmatlari', template_mode='bootstrap3', index_view=SecureAdminIndexView())
admin.add_view(SecureModelView(User, db.session))

# Bosh sahifa
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        full_name = request.form['full_name']
        passport_number = request.form['passport_number']
        phone_number = request.form['phone_number']
        service_type = request.form['service_type']
        service_number = randint(100000, 999999)

        ariza = User(
            full_name=full_name,
            passport_number=passport_number,
            phone_number=phone_number,
            service_type=service_type,
            service_number=service_number
        )
        db.session.add(ariza)
        db.session.commit()

        flash(f"{full_name} tomonidan '{service_type}' xizmatiga ariza yaratildi. Xizmat raqamingiz: #{service_number}", 'success')
        return render_template("index.html", response=ariza)

    return render_template("index.html")

# ...existing code...

# Admin login routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = AdminUser.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin.index'))
        else:
            flash('Noto\'g\'ri login yoki parol', 'error')
    
    return render_template('admin/login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('admin_login'))

# ...existing code...
# PDF export
@app.route('/generate-pdf/<int:service_id>')
def generate_pdf(service_id):
    service = User.query.get_or_404(service_id)
    html = render_template_string('''
        <h1>Davlat xizmati arizasi</h1>
        <p><strong>F.I.Sh:</strong> {{ s.full_name }}</p>
        <p><strong>Pasport:</strong> {{ s.passport_number }}</p>
        <p><strong>Telefon:</strong> {{ s.phone_number }}</p>
        <p><strong>Xizmat turi:</strong> {{ s.service_type }}</p>
        <p><strong>Xizmat raqami:</strong> #{{ s.service_number }}</p>
        <p><strong>Yaratilgan vaqti:</strong> {{ s.created_at }}</p>
    ''', s=service)

    pdf = BytesIO()
    pisa.CreatePDF(BytesIO(html.encode('utf-8')), dest=pdf)
    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=ariza_{service.service_number}.pdf'
    return response

# Run
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
