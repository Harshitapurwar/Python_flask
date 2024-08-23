from datetime import datetime
from app import db,Mail, login_manager,app
from flask_mail import Mail, Message
from flask import url_for
from app import mail
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer
from itsdangerous import TimedSerializer
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
# from config import SECRET_KEY
from datetime import datetime, timedelta
# from itsdangerous import TimedSerializer, SignatureExpired, BadSignature
# from config import SECRET_KEY


class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # password_hash = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(128))
    chat_messages = db.relationship('ChatMessage', back_populates='user')
    oauth_accounts = db.relationship('OAuth', back_populates='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_reset_token(self):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
            return data.get('user_id')
        except Exception as e:
            return None  
        return User.query.get(user_id)
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    
class OAuth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50))
    provider_user_id = db.Column(db.String(256), unique=True)
    token = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', back_populates='oauth_accounts')


class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fname = db.Column(db.String(50), nullable=False)
    lname = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(15))
    street = db.Column(db.String(100))
    city = db.Column(db.String(50))
    postal_code = db.Column(db.String(20))
    state = db.Column(db.String(50))
    country = db.Column(db.String(50))
    avatar = db.Column(db.String(100))
    
    def __repr__(self):
        return f'<UserProfile {self.fname} {self.lname}>'

class WorkerProfile(db.Model):
    __tablename__ = 'worker_profile'
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(50), nullable=False)
    lname = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(15))
    street = db.Column(db.String(100))
    city = db.Column(db.String(50))
    postal_code = db.Column(db.String(20))
    state = db.Column(db.String(50))
    country = db.Column(db.String(50))
    avatar = db.Column(db.String(100))
    service_type = db.Column(db.String(100), nullable=False)
    chat_messages = db.relationship('ChatMessage', back_populates='worker')

    def __repr__(self):
        return f"<WorkerProfile fname={self.fname}, lname={self.lname}, phone={self.phone}>"

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    worker_id = db.Column(db.Integer, db.ForeignKey('worker_profile.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)

    user = db.relationship('User', back_populates='chat_messages')
    worker = db.relationship('WorkerProfile', back_populates='chat_messages')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))