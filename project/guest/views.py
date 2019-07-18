from project import app, db
from project.models import User, Admin, Proposal, Department,Project,Progress_report,Progress_comment
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for,make_response
from flask_login import login_user,login_required, logout_user
from .forms import LoginForm
from project.models import User
from project import db, login_manager
import functools
from flask_login import login_user,login_required,logout_user
import logging
import datetime,json
from json import dumps
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
            return make_response('Invalid Token',401,{'www-Authenticate':'Invalid Token"'})
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'])
            current_user = Guest.query.filter_by(publicID=data['public_id']).first()
        except:
            return make_response('Invalid Token',401,{'www-Authenticate':'Invalid Token"'})
        return f(current_user,*args,**kwargs)   
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

    
class Logout2(Resource):
    @token_required
##    @staticmethod
    @login_required
    def post(self,current_user):
        logout_user()
        flash('You were logged out. ')
##        return redirect(url_for(''))

class PostProject_(Resource):
    @token_required
##    @staticmethod
    def post(self,current_user):
        data = request.get_json()
##        form = ProjectForm(request.form)
        ## formate date
##        date_submit = datetime.date.today()
        ## report = TextField('Upload File',validators=[DataRequired()])
##        if request.method == 'post':
               ## return redirect(request.url)
        p=datetime.date.today()
        fln = Project(title=data['title'] ,comments=data['comments'],date_submit=p)
        db.session.add(fln)
        db.session.commit()
        return fln.json()

    @token_required
    def delete(self,current_user):
        data = request.get_json()
        proj=Project.query.filter_by(title=data['title']).first()
        db.session.delete(proj)
        db.session.commit()
        return {'status':'succces'}

    @token_required
    def put(self,current_user):
        data = request.get_json()
        proj=Project.query.filter_by(title=data['title']).first()
        proj.title=request.json.get('title',proj.title)
        proj.comments=request.json.get('comments',proj.comments)
        db.session.commit()
        return jsonify({'proj':proj})
##                flash('File Uploaded')


class AssignedProposal(Resource):
    @token_required
##    @staticmethod  
    def get(current_user):
        data = request.get_json()
        email = data['email']
        project = Proposal.query.filter_by(email=email)
        ## will need to iterate through the recode project like the for loop
        return [x.json() for x in project]

class ProgressComment(Resource):
    @token_required
    def post(current_user):
        data = request.get_json()
        comment = Progress_comment(reg_no=data['reg_no'],body=data['body'])
        db.session.add(comment)
        db.session.commit()
        return data

class Reports(Resource):
    @token_required
    def post(current_user):
        data = request.get_json()
        reports = Progress_comment.query.filter_by(reg_no=data['reg_no']).first()
        return reports.body



        

        
