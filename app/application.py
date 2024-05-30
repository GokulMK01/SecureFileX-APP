# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import LoginManager
# from flask_login import UserMixin, login_manager, current_user
# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import LoginManager

# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'your_secret_key'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../app.db'
# db = SQLAlchemy(app)
# login_manager = LoginManager(app)
# app.debug = True
# from . import routes
# from . import models
# from app import routes
# from .models import User
# @login_manager.user_loader
# def load_user(user_id):
#     from app.models import User

#     return User.query.get(int(user_id)) 
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../app.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)

from . import routes  # Import routes after initializing app, db, and login_manager
from . import models  # Import models after initializing db

@login_manager.user_loader
def load_user(user_id):
    from .models import User
    return User.query.get(int(user_id))



