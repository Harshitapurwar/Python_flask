from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
# from config import Config
# from config import SECRET_KEY, MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD
import os
app = Flask(__name__)
app.config.from_pyfile('config.py')
# app.config.from_object(Config)
mail = Mail(app)
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'static/uploads'
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# app.config['SESSION_TYPE'] = 'filesystem'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['MAIL_SERVER'] = MAIL_SERVER
# app.config['MAIL_PORT'] = MAIL_PORT
# app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
# app.config['MAIL_USE_SSL'] = False
# app.config['MAIL_USERNAME'] = MAIL_USERNAME
# app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
# app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# Import the routes after the app and db are initialized

from routes import *

if __name__ == '__main__':
    app.run(debug=True)
