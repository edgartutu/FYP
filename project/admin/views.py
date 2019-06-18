from project import app, db
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for
from flask.ext.login import login_user,login_required, logout_user
from .forms import LoginForm
from project.models import User, bcrypt 
import functools
api = Api(app)

class Admin(Resource):
    
                

        
