from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from datetime import datetime
import pyotp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import os
# pip install pyotp qrcode Pillow - für Google Authenticator
import qrcode
from io import BytesIO
import base64
import sqlite3
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_BINDS'] = {
    'job_requirements': 'sqlite:///job_requirements.db',
    'bewerber':'sqlite:///bewerber.db'
}
db = SQLAlchemy(app)
def derive_key(password: str, salt: bytes) -> bytes:
    # Use PBKDF2HMAC to derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet key length
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Example usage
password = input("Enter your password: ")
salt = os.urandom(16)  # Generate a random salt
fernet_key = derive_key(password, salt)
f = Fernet(fernet_key)



def setup_2fa_for_user(user):
    # Erzeuge ein zufälliges Geheimnis (Base32 kodiert)
    user.two_factor_secret = pyotp.random_base32()
    db.session.commit()
    return user.two_factor_secret

class employees_a(db.Model):
    __bind_key__='bewerber'
    id = db.Column(db.Integer, primary_key=True)
    job = db.Column(db.String(255))
    vorname = db.Column(db.String(255))
    nachname = db.Column(db.String(255))
    email = db.Column(db.String(255))
    geburtstag = db.Column(db.String(255))
    berufserfahrung = db.Column(db.String(255))
    qualifikation = db.Column(db.String(255))
    ausbildung = db.Column(db.String(255))
    score = db.Column(db.Float)

class User_a(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))
    initial_pw = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20))  # 'fuehrungskraft' oder 'mitarbeiter'
    two_factor_secret = db.Column(db.String(16), nullable=True)
    key = db.Column(db.String(100))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.LargeBinary)
    password = db.Column(db.LargeBinary)
    initial_pw = db.Column(db.LargeBinary)
    role = db.Column(db.LargeBinary)
    two_factor_secret = db.Column(db.LargeBinary)
    key = db.Column(db.LargeBinary)


class Keys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    salt = db.Column(db.LargeBinary)
    pw = db.Column(db.String(100))
    
    
class job_requirements(db.Model):
    __bind_key__='job_requirements'
    id = db.Column(db.Integer, primary_key=True)
    jobname = db.Column(db.String(255))
    experience = db.Column(db.String(255))
    qualifications = db.Column(db.String(255))
    education = db.Column(db.String(255))
    location = db.Column(db.String(50))
    weight_experience = db.Column(db.Float)
    weight_qualifications = db.Column(db.Float)
    weight_education = db.Column(db.Float)

class employees(db.Model):
    __bind_key__='bewerber'
    id = db.Column(db.Integer, primary_key=True)
    job = db.Column(db.LargeBinary)
    vorname = db.Column(db.LargeBinary)
    nachname = db.Column(db.LargeBinary)
    email = db.Column(db.LargeBinary)
    geburtstag = db.Column(db.LargeBinary)
    berufserfahrung = db.Column(db.LargeBinary)
    qualifikation = db.Column(db.LargeBinary)
    ausbildung = db.Column(db.LargeBinary)
    score = db.Column(db.LargeBinary)


    
class atachmant(db.Model):
    __bind_key__='bewerber'
    id = db.Column(db.Integer, primary_key=True)
    id_employees = db.Column(db.ForeignKey(employees.id))
    pdf = db.Column(db.LargeBinary)

def reset_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.add(Keys(salt=salt,pw=hashed_password))
        
        db.session.add(job_requirements(jobname="Schweißer",experience="> 5 Jahre",qualifications="Sprache: Deutsch",education="Abgeschlossene Berufsausbildung",location="Kreischa",weight_experience="0.5",weight_qualifications="0.3",weight_education="0.2"))
        db.session.add(job_requirements(jobname="Sekräterin",experience="< 3 Jahre",qualifications="Deutsch: fließend",education="Ausbildung",location="Kreischa",weight_experience="0.3",weight_qualifications="0.4",weight_education="0.5"))
        db.session.add(job_requirements(jobname="Geschäftführung Finanzen",experience=">= 10 Jahre als Geschäftsführung Finanzen",qualifications="Deutsch: fließend; Englisch: fließend;",education="Master in Finanzwesen, Wirtschaft, BWL, VWL oder MBA",location="Kreischa",weight_experience="0.4",weight_qualifications="0.4",weight_education="0.2"))
        
        key = Fernet.generate_key()
        encry_key = f.encrypt(key)
        hashed_password = generate_password_hash("qwe", method='pbkdf2:sha256')
        db.session.add(User(two_factor_secret=f.encrypt("".encode("utf-8")),initial_pw=f.encrypt(str(False).encode("utf-8")),email=f.encrypt("qq@qq.de".encode("utf-8")), password=f.encrypt(hashed_password.encode("utf-8")), role=f.encrypt("fuehrungskraft".encode("utf-8")),key=encry_key))
        db.session.add(User_a(email="",password="",role="",key=""))

        hashed_password = generate_password_hash("qwe", method='pbkdf2:sha256')
        db.session.add(User(two_factor_secret=f.encrypt("".encode("utf-8")),initial_pw=f.encrypt(str(False).encode("utf-8")),email=f.encrypt("qwe@qq.de".encode("utf-8")), password=f.encrypt(hashed_password.encode("utf-8")), role=f.encrypt("mitarbeiter".encode("utf-8")),key=encry_key))

        hashed_password = generate_password_hash("qwe", method='pbkdf2:sha256')
        db.session.add(User(two_factor_secret=f.encrypt("".encode("utf-8")),initial_pw=f.encrypt(str(False).encode("utf-8")),email=f.encrypt("qweq@qq.de".encode("utf-8")), password=f.encrypt(hashed_password.encode("utf-8")), role=f.encrypt("mitarbeiter".encode("utf-8")),key=encry_key))
        
        mf = Fernet(key)
        s = "Schweißer"
        s = s.encode("utf-8")
        score = 62 
        db.session.add(employees(job=f.encrypt(s),vorname=f.encrypt(b"Caspar"),nachname=f.encrypt(b"Schmidt"),email=f.encrypt(b"test@test.com"),geburtstag=f.encrypt(b"1990-01-01"), berufserfahrung=f.encrypt(b"10 Jahre als Schweisser und 2 Jahre als Recruiter"),qualifikation=f.encrypt(b"Sprachen C1 in Englisch"),ausbildung=f.encrypt(b"Bachelor in Wirtschaftsinformatik und Master in BWL"),score=f.encrypt(str(score).encode("utf-8"))))
        score = 25
        db.session.add(employees(job=f.encrypt(s),vorname=f.encrypt(b"Clemens"),nachname=f.encrypt(b"Teubner"),email=f.encrypt(b"test@test.com"),geburtstag=f.encrypt(b"1011-01-01"), berufserfahrung=f.encrypt(b""),qualifikation=f.encrypt(b""),ausbildung=f.encrypt(b""),score=f.encrypt(str(score).encode("utf-8"))))
        score = 53
        db.session.add(employees(job=f.encrypt(s),vorname=f.encrypt(b"Julius"),nachname=f.encrypt(b"Kunzak"),email=f.encrypt(b"test@tester.com"),geburtstag=f.encrypt(b"14.06.2004"), berufserfahrung=f.encrypt("5 Jahre als Schweißer".encode("utf-8")),qualifikation=f.encrypt(b"Deusch, Englisch und Japanisch"),ausbildung=f.encrypt(b"abgeschlossene Berufsausbildung"),score=f.encrypt(str(score).encode("utf-8"))))
        score = 37.24
        db.session.add(employees(job=f.encrypt(s),vorname=f.encrypt(b"Max"),nachname=f.encrypt(b"Mustermann"),email=f.encrypt(b"maxmustermann@maxmustermann.com"),geburtstag=f.encrypt(b"01.01.1999"), berufserfahrung=f.encrypt("abgeschlossene berufsausbildung zum fahrradmechtroniker, 2 jahre als schweißer, 3 jahre als busfahrer".encode("utf-8")),qualifikation=f.encrypt("doktor, medizinerfahrungerfahrer, entwicklung, von, webanwendungen, mit, javascript, react, und, node, js, verwaltung, von, datenbanken, mit, postgresql, und, mongodb, zusammenarbeit, mit, internationalen, teamshigkeitensprachen, python, java, c, +, +2, c1, fluently, Deutsch (B2) - Englisch (C1) - Spanisch (fließend)".encode("utf-8")),ausbildung=f.encrypt(b"abgeschlossene Berufsausbildung zum Fahrradmechtroniker Doktor in Doktor der Medizin"),score=f.encrypt(str(score).encode("utf-8"))))
        db.session.add(employees_a())
        db.session.commit()

if __name__ == "__main__":
    reset_db()
