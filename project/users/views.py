from project import app, db
from project.models import User, Admin,Progress_comment,Progress_report, Proposal,Previous_topic,Department,Project,Rejected_Proposal
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for,make_response
from flask_login import login_user,login_required, logout_user
from .forms import LoginForm,RegisterForm,Proposal_submittion_Form
from project.models import User
from project import db, login_manager
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash,check_password_hash
import os
import functools
from flask_login import login_user,login_required,logout_user
import json
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
            return make_response('Invalid Token',401,{'www-Authenticate':'Invalid Token"'})
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'])
            current_user = User.query.filter_by(publicID=data['public_id']).first()
        except:
            return make_response('Invalid Token',401,{'www-Authenticate':'Invalid Token"'})
        return f(current_user,*args,**kwargs)   
    return decorated


class Register(Resource):
    
    @staticmethod
    def post(email,reg_no,password,confirm_password):
        '''Generating public ID'''
        publicID = str(uuid.uuid4())
        
        form = RegisterForm()
        try:
            reg_no,email, password = request.json.get('reg_no').strip(), request.json.get('email').strip(),request.json.get('password').strip()
        except Exception as why:
            # Log input strip or etc. errors.
            logging.info("Username, password or email is wrong. " + str(why))
            flash('status:invalid input')
        if reg_no is None or password is None :
            flash ('status:field non')
        if password==confirm_password:   
            if form.validate_on_submit():
                user = User(email=form.email.data,reg_no=form.reg_no.data,publicID=publicID,password=form.password.data)
                if user is not None:
                    flash ('status:user exist')
                # Create a new user.
                db.session.add(user)
                db.session.commit()
                flash('status registration completed.')
        else:
            flash('passwords dont match!!!!!')
    ##            return redirect(url_for())


##class Login(Resource):
####    @staticmethod
####    @login_required
##    def post(reg_no,password):
##        error=None
##        form = LoginForm()
##        try:
##            reg_no, password = request.json.get('reg_no').strip(), request.json.get('password').strip()
##            print(reg_no , password)
##        except Exception as why:
##            logging.info("reg_no or password is wrong. " + str(why))
##            flash ('status: invalid input.')
##        if reg_no is None or password is None:
##            flash ('status: user information is none.') 
##        
##        if request.method =='POST':
##            if form.validate_on_submit():
##                user = User.query.filter_by(reg_no=form.reg_no.data).first()
##                if user is None:
##                    flash ('status: user doesnt exist.')
##                elif user is not None and user.check_password(form.password.data):
##                    login_user(user)
##                    flash('You were logged in.')
####                    return redirect(url_for())
##                else:
##                    error = 'Invalid registration number or password'
####        return render_template('try.html',form=form,error=error)

class Login1(Resource):
    def get(self):
        auth = request.authorization
        '''checking if authorization information is complete'''
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify1',401,{'www-Authenticate':'Basic realm-"login required!"'})        
        admin = User.query.filter_by(reg_no=auth.username).first()
        if not admin:
            return make_response('Could not verify2',401,{'www-Authenticate':'Basic realm-"login required!"'})       
##        if check_password_hash(admin.password,auth.password):
        if admin.password_hash == auth.password:
            token = jwt.encode({'public_id':admin.publicID,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=60)},app.config['SECRET_KEY'])
            return jsonify({'token':token.decode('UTF-8')})
        return make_response('Could not verify3',401,{'www-Authenticate':'Basic realm-"login required!"'})


class Logout1(Resource):
    @token_required
##    @staticmethod
##    @login_required
    def post(current_user):
        logout_user()
        flash('You were logged out.')
##        return redirect(url_for(''))


class ResetPassword(Resource):
    
    def post(self):
        old_pass, new_pass = request.json.get('old_pass'), request.json.get('new_pass')
        user = User.query.filter_by(email=email).first()
        if user.password != old_pass:
            flash ('status: old password does not match.')
        user.password = new_pass
        db.session.commit()
        flash('status: password changed.')
##        return redirect(url_for())
        
                
class GetAllProjects(Resource):
    @token_required
    def get(self,current_user):
        project = Project.query.all()
        return [x.json() for x in project]


class PostProposals(Resource):
##    @token_required
##    @staticmethod  
    def post(current_user):

        data = request.form
        title = data['title']
        reg_no = data['reg_no']
        problem_statement = data['problem_statement']
        abstract = data['abstract']
        reg_no2 = data['reg_no2']
        student1 = data['student1']
        student2 = data['student2']

        file = request.files['file']
        filename = secure_filename(file.filename)
        
        fileExt = filename.split('.')[1]
        autoGenFileName = uuid.uuid4()

        newFilename = str(autoGenFileName)+'.'+fileExt

        file.save(os.path.join(app.config['UPLOAD_FOLDER'],newFilename))

        '''Done not forget to change the proposal upload to a byte type object'''
##        header = {'Content-Type':'text/html'}    
##        form = Proposal_submittion_Form()   
        status = 'pending'
        supervisor = 'None'
        email = 'None'
        comment = 'None'

        p_upload = Proposal(title=title,reg_no=reg_no,problem_statement=problem_statement,
                            abstract=abstract ,reg_no2=reg_no2,proposal_uploadfile=newFilename,
                            status=status,supervisor=supervisor,email=email,
                            comment=comment,student1=student1,student2=student2)

        db.session.add(p_upload)
        db.session.commit()
        return data

    @token_required
    def delete(self,current_user):
        data = request.get_json()
        prop=Proposal.query.filter_by(title=data['title']).first()
        db.session.delete(prop)
        db.session.commit()
        return {'status':'succces'}

    @token_required
    def put(self,current_user):
        data = request.get_json()
        prop=Proposal.query.filter_by(title=data['title']).first()
        prop.title=request.json.get('title',prop.title)
        prop.problem_statment=request.json.get('problem_statment',prop.problem_statment)
        prop.abstract=request.json.get('abstract',prop.abstract)
        prop.proposal_uploadfile=request.json.get('proposal_uploadfile',prop.proposal_uploadfile)
        prop.student_pair=request.json.get('student_pair',prop.student_pair)
        db.session.commit()
        return jsonify({'pro':prop})
         
class ViewPrjects(Resource):
#    @token_required
##    @staticmethod
    def post(current_user):
        data = request.get_json()
####        data = {"reg_no":"1234"}
        error = None
        project = Proposal.query.filter_by(reg_no=str(data['reg_no']))
####        rejected = Rejected_Proposal.query.filter_by(reg_no=data['reg_no']).first()
        return [x.json() for x in project]
#        for y in rejected:
#            return y.json(),project
                
                        
class ViewProposals(Resource):
##    @token_required
##    @staticmethod
    def get(current_user):
        students = Project.query.all()
        return [x.json() for x in students]
        
class PostProgressReport(Resource):
#    @token_required
    def post(current_user):
        data = request.get_json()
        date_s = datetime.datetime.today()
        datestamp = date_s.strftime('%d-%m-%Y')
        reg_no1 = data['reg_no']
        files = data['files']
        supervisor = Proposal.query.filter_by(reg_no=reg_no1).first()
        s_email = supervisor.email

        progress = Progress_report(reg_no=reg_no1,files=files,supervisor_email=s_email,datestamp=datestamp)
        db.session.add(progress)
        db.session.commit()

        return data

class Previous_topics_by_title(Resource):
    @token_required
    def get(current_user):
        data = request.get_json()
        topic = Previous_topic.query.filter_by(title=data['title']).first()
        try:
            return topic.json()
        except Exception:
            return "No reports available by that title"

class Previous_topics_by_year(Resource):
#    @token_required
    def get(current_user):
        data = request.get_json()
        topic = Previous_topic.query.all()
#        try:
        return [x.json() for x in topic]
        
#        except Exception:
#            return "No reports available for that year"

class UpdateAbstract(Resource):
#    @token_required
    def post(current_user):
        data = request.get_json()
        update = Proposal.query.filter_by(reg_no=data['reg_no']).first()
        update.abstract = data['abstract']
        db.session.commit()
#        try:
#            return update.json()

#        except Exception:
#            return "Error, Operation unsuccessful"





    
        
