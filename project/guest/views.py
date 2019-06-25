from project import app, db
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for
from flask_login import login_user,login_required, logout_user
from .forms import LoginForm
from project.models import User,Guest
from project import db, login_manager
import functools
from flask_login import login_user,login_required,logout_user
import logging

from flask import jsonify
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
from functools import wraps
import datetime

api = Api(app)

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message':'Token is missing'}),401

        try:
            data = jwt.decode(token,app.config['SECRET_KEY'])
            current_user = Guest.query.filter_by(publicID=data['publicID']).first()

        except:
            return jsonify({'message':'Token is invalid'}),401

        return f(curent_user,*args,**kwargs)
    
    return decorated

##class Login(Resource):
##    @staticmethod
##    @login_required
##    def post():
##        error=None
##        form = LoginForm(request.form)
##        try:
##            email, password = request.json.get('email').strip(), request.json.get('password').strip()
##            print(email , password)
##        except Exception as why:
##            logging.info("reg_no or password is wrong. " + str(why))
##            flash ('status: invalid input.')
##        if email is None or password is None:
##            flash ('status: user information is none.') 
##        
##        if request.method =='POST':
##            if form.validate_on_submit():
##                guest = Guest.query.filter_by(email=email, password=password).first()
##                if guest is None:
##                    flash ('status: user doesnt exist.')
##                elif guest is not None and check_password_hash(
##                    user.password, request.form['password']):
##                    login_user(guest)
##                    flash('You were logged in.')
####                    return redirect(url_for())
##                else:
##                    error = 'Invalid email or password'
##        return render_template('login.html',form=form,error=error)

class Login2(Resource):
    def get(self):
        auth = request.authorization
        '''checking if authorization information is complete'''
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify1',401,{'www-Authenticate':'Basic realm-"login required!"'})
        
        admin = Guest.query.filter_by(email=auth.username).first()

        if not admin:
            return make_response('Could not verify2',401,{'www-Authenticate':'Basic realm-"login required!"'})
        
##        if check_password_hash(admin.password,auth.password):
        if admin.password_hash == auth.password:
            token = jwt.encode({'public_id':admin.publicID,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=60)},app.config['SECRET_KEY'])
            return jsonify({'token':token.decode('UTF-8')})
        return make_response('Could not verify3',401,{'www-Authenticate':'Basic realm-"login required!"'})

    
class Logout(Resource):
    @token_required
    @staticmethod
    @login_required
    def post(current_user):
        logout_user()
        flash('You were logged out. ')
##        return redirect(url_for(''))

class PostProject(Resource):
    @token_required
    @staticmethod
    def post(current_user,title,comments,report_uploadfile,date_submit):
##        form = ProjectForm(request.form)
        ## formate date
        date_submit = datetime.date.today()
        ## report = TextField('Upload File',validators=[DataRequired()])
        if request.method == 'post':
               ## return redirect(request.url)
                fln = Project(title=title ,comments=comments,date_submit=date_submit)
                db.session.add(fln)
                db.session.commit()
                return fln.json()
##                flash('File Uploaded')


class AssignedProposal(Resource):
    @token_required
    @staticmethod
    def get(current_user):
        project = Proposal.query.all()
        ## will need to iterate through the recode project like the for loop
        return project
    
