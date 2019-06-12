## set up of our db file

import os
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager


login_manager=LoginManager()

app=Flask(__name__)

app.config['SECRET_KEY'] = 'mysecretkey'

################# SQL DATABASE SECTION ##########

basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///'+os.path.join(basedir,'data.sql')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] =False

db = SQLAlchemy(app)

Migrate(app,db)

login_manager.init_app(app)

login_manager.login_view ='login'
