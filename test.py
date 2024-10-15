import os
from flask import Flask, request, jsonify, url_for, render_template, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from dotenv import load_dotenv
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root_2005@localhost/practice'
app.config['SECURITY_PASSWORD_SALT'] = 'your_salt'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'prakrutipanchal2005@gmail.com'
app.config['MAIL_DEFAULT_SENDER'] = 'prakrutipanchal2005@gmail.com'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

load_dotenv()
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class Account(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    role = db.Column(db.String(50), nullable=False, default='user')  # Add role column

with app.app_context():
    db.create_all()

@app.before_request
def make_session_permanent():
    session.permanent = True

@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))

def send_confirmation_email(email):
    token = generate_reset_token(email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email.." 
    msg = Message(subject, recipients=[email], html=html)
    mail.send(msg)
    
def generate_reset_token(email):
    return serializer.dumps(email, app.config['SECURITY_PASSWORD_SALT'])

def confirm_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

def reset_token_mail(token, email):
    try:
        with app.app_context():
            msg = Message(
                subject="Password reset Token",
                recipients=[email],
                sender=app.config['MAIL_USERNAME'],
                body=f"Token sent successfully..{token}"
            )
            mail.send(msg) 
    except smtplib.SMTPException as e:
        print(f"Token authentication failed {e}")

@app.post('/register')
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
    role = data.get('role', 'user')  # Default role is 'user'
    new_account = Account(
        username=data.get('username'),
        password=hashed_password,
        email=data.get('email'),
        role=role
    )
    db.session.add(new_account)
    db.session.commit()
    send_confirmation_email(new_account.email)
    return jsonify({"Message": "User registered successfully, please check your mail to confirm your account!"})

@app.get('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_reset_token(token)
    except:
        return jsonify({"Message": "Token is invalid or has expired!"}), 400 

    account = Account.query.filter_by(email=email).first()
    if account.confirmed:
        return jsonify({"Message": "Account is already created. You can login now."}), 200
    else:
        account.confirmed = True
        account.confirmed_on = datetime.utcnow()
        db.session.add(account)
        db.session.commit()
        return jsonify({'Message': 'You have confirmed your account. Thanks!'}), 200

@app.post('/request_reset_password')
def request_reset_password():
    data = request.get_json()
    username = data.get('username')
    account = Account.query.filter_by(username=username).first()
    if account:
        token = generate_reset_token(username)
        reset_token_mail(token, account.email)
    return jsonify({"Message": "Token has been sent successfully. Please check your mail to reset the password!"}), 200

@app.post('/reset_password')
def reset_password():
    data = request.get_json()
    username = confirm_reset_token(data.get('token'))
    if username:
        account = Account.query.filter_by(username=username).first()
        if account:
            password = data.get('password')
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            account.password = hashed_password
            db.session.commit()
            return jsonify({"Message": "Password has been changed successfully."})
    return jsonify({"Message": "Invalid credentials."})

@app.post('/login')
def login():
    data = request.get_json()
    account = Account.query.filter_by(username=data.get('username')).first()
    if account:
        password = bcrypt.check_password_hash(account.password, data.get('password'))
        if password:
            login_user(account)
            session.permanent = True
        return jsonify({'Message': 'User logged in successfully!'}), 200
    return jsonify({'Message': 'Invalid username or password!'}), 401

@app.post('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'Message': 'User logged out successfully!'}), 200

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.get('/admin_dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    return jsonify({"Message": "Welcome to the admin dashboard!"})

@app.get('/user_dashboard')
@login_required
@role_required('user')
def user_dashboard():
    return jsonify({"Message": "Welcome to the user dashboard!"})

@app.errorhandler(403)
def access_forbidden(error):
    return jsonify({"Message": "You do not have permission to access this resource."}), 403

if __name__ == '__main__':
    app.run(debug=True)
