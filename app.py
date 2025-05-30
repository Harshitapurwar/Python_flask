from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
import os
app = Flask(__name__)
app.config.from_pyfile('config.py')
# app.config.from_object(Config)
mail = Mail(app)
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'static/uploads'

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# Import the routes after the app and db are initialized

from routes import *
if __name__ == '__main__':
    app.run(debug=True)

# if __name__ == '__main__':
#     from waitress import serve
#     serve(app, host="0.0.0.0", port=8080)
#     # app.run(debug=True)
