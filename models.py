from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from datetime import datetime
import pyotp
# pip install pyotp qrcode Pillow - für Google Authenticator
import qrcode
from io import BytesIO
import base64
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
def setup_2fa_for_user(user):
    # Erzeuge ein zufälliges Geheimnis (Base32 kodiert)
    user.two_factor_secret = pyotp.random_base32()
    db.session.commit()
    return user.two_factor_secret

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    initial_pw = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20))  # 'fuehrungskraft' oder 'mitarbeiter'
    two_factor_secret = db.Column(db.String(16), nullable=True)
    
def reset_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        hashed_password = generate_password_hash("qwe", method='pbkdf2:sha256')
        db.session.add(User(email="qq@qq.de", password=hashed_password, role="fuehrungskraft"))
        hashed_password = generate_password_hash("qwe", method='pbkdf2:sha256')
        db.session.add(User(email="qwe@qq.de", password=hashed_password, role="mitarbeiter"))
        hashed_password = generate_password_hash("qwe", method='pbkdf2:sha256')
        db.session.add(User(email="qweq@qq.de", password=hashed_password, role="mitarbeiter"))
        db.session.commit()

if __name__ == "__main__":
    reset_db()
