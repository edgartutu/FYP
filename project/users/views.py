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
            current_user = User.query.filter_by(reg_no=data['reg_no']).first()
        except:
            return make_response('Invalid Token',401,{'www-Authenticate':'Invalid Token"'})
        return f(current_user,*args,**kwargs)   
    return decorated


class Register(Resource):
    
    #@staticmethod
    def post(self):
        '''Generating public ID'''
        publicID = str(uuid.uuid4())
        data = request.get_json()
        student1 = data['student1']
        student2 = data['student2']
        reg_no = data['reg_no']
        reg_no2 = data['reg_no2']
        email = data['email']
        email2 = data['email2']
        tel = data['tel']
        tel2 = data['tel2']
        course = data['course']
        password = data['password']
        confirm_password = data['confirm_password']

        #form = RegisterForm()
        #try:
        #    reg_no,email, password = request.json.get('reg_no').strip(), request.json.get('email').strip(),request.json.get('password').strip()
        #except Exception as why:
            # Log input strip or etc. errors.
        #    logging.info("Username, password or email is wrong. " + str(why))
        #    flash('status:invalid input')
        if reg_no is None or password is None :
            return {'error':'error'}

        if password==confirm_password:   
            user = User(student1=student1,student2=student2,reg_no=reg_no,reg_no2=reg_no2,email=email,tel=tel,
                        email2=email2,tel2=tel2,password_hash=password,course=course)
            db.session.add(user)
            db.session.commit()
                #flash('status registration completed.')
        else:
            return {'error':'Could not creat account'}


class Login1(Resource):
    def post(self):
        auth = request.authorization
        data = request.get_json()
        
        '''checking if authorization information is complete'''
        if not data or not data['username'] or not data['password']:
            return make_response('Could not verify1',401,{'www-Authenticate':'Basic realm-"login required!"'})        
        admin = User.query.filter_by(reg_no=data['username']).first()
        if not admin:
            return make_response('Could not verify2',401,{'www-Authenticate':'Basic realm-"login required!"'})       
        if check_password_hash(admin.password_hash,data['password']):
            token = jwt.encode({'reg_no':admin.reg_no,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=60)},app.config['SECRET_KEY'])
            return jsonify({'token':token.decode('UTF-8'),'username':admin.reg_no})
        return make_response('Could not verify3',401,{'www-Authenticate':'Basic realm-"login required!"'})


class Logout1(Resource):
#    @token_required
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
    #@token_required
    def get(self,current_user):
        project = Project.query.all()
        return [x.json() for x in project]


class PostProposals(Resource):
    #@token_required
##    @staticmethod  
    def post(current_user):

        data = request.form
        reg_nox = data['reg_nox']
        title = data['title']
        #reg_no = data['reg_no']
        proposal_ref = data['proposal_ref']
        problem_statement = data['problem_statement']
        methodology = data['methodology']
        #reg_no2 = data['reg_no2']
        #student1 = data['student1']
        #student2 = data['student2']
        file = request.files['file']
        filename = secure_filename(file.filename)
        fileExt = filename.split('.')[1]
        autoGenFileName = uuid.uuid4()
        newFilename = str(autoGenFileName)+'.'+fileExt
        file.save(os.path.join(app.config['UPLOAD_FOLDER'],newFilename))

        user = User.query.filter_by(reg_no=reg_nox).first()
        reg_no = user.reg_no
        reg_no2 = user.reg_no2
        student1 = user.student1
        student2 = user.student2

        status = 'pending'
        supervisor = 'None'
        email = 'None'
        comment = 'None'
        id = ''

        p_upload = Proposal(id=id,title=title,reg_no=reg_no,project_ref=proposal_ref,problem_statement=problem_statement,
                            methodology=methodology ,reg_no2=reg_no2,proposal_uploadfile=newFilename,
                            status=status,supervisor=supervisor,email=email,
                            comment=comment,student1=student1,student2=student2)

        db.session.add(p_upload)
        db.session.commit()
        return data

    def delete(current_user):
        data = request.get_json()
        prop=Proposal.query.filter_by(title=data['title']).first()
        db.session.delete(prop)
        db.session.commit()
        return {'status':'succces'}

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
    #@token_required
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
    #@token_required
##    @staticmethod
    def get(current_user):
        students = Project.query.all()
        return [x.json() for x in students]
        
class PostProgressReport(Resource):
    #@token_required
    def post(current_user):

        data = request.form
        date_s = datetime.datetime.today()
        
        datestamp = date_s.strftime('%d-%m-%Y')
        reg_no1 = data['reg_no']
        comment = data['comment']

        file = request.files['file']
        filename = secure_filename(file.filename)
        
        fileExt = filename.split('.')[1]
        autoGenFileName = uuid.uuid4()

        newFilename = str(autoGenFileName)+'.'+fileExt

        file.save(os.path.join(app.config['UPLOAD_FOLDER'],newFilename))
        
        supervisor = Proposal.query.filter_by(reg_no=reg_no1).first()
        s_email = supervisor.email

        progress = Progress_report(reg_no=reg_no1,files=newFilename,supervisor_email=s_email,datestamp=datestamp,comment=comment)
        db.session.add(progress)
        db.session.commit()

        return data

class Previous_topics_by_title(Resource):
    #@token_required
    def get(current_user):
        data = request.get_json()
        topic = Previous_topic.query.filter_by(title=data['title']).first()
        try:
            return topic.json()
        except Exception:
            return {'title':'No data available'}

class Previous_topics_by_year(Resource):
#    @token_required
    def get(current_user):
        data = request.get_json()
        topic = Previous_topic.query.all()
#        try:
        return [x.json() for x in topic]
        
#        except Exception:
#            return "No reports available for that year"

class UpdateMethodology(Resource):
#    @token_required
    def post(current_user):
        data = request.get_json()
        update = Proposal.query.filter_by(reg_no=data['reg_no']).first()
        update.methodology = data['methodology']
        db.session.commit()
#        try:
#            return update.json()

#        except Exception:
#            return "Error, Operation unsuccessful"

# add routes
class resubmitfiles(Resource):
#    @token_required
    def post(current_user):
        data = request.get_json()
        update = Proposal.query.filter_by(reg_no=data['reg_no']).first()

        file = request.files['file']
        filename = secure_filename(file.filename)
        
        fileExt = filename.split('.')[1]
        autoGenFileName = uuid.uuid4()

        newFilename = str(autoGenFileName)+'.'+fileExt

        file.save(os.path.join(app.config['UPLOAD_FOLDER'],newFilename))

        update.proposal_uploadfile = newFilename
        db.session.commit()

class deleteproposal(Resource):
#    @token_required
    def post(current_user):
        data = request.get_json()
        update = Proposal.query.filter_by(reg_no=data['reg_no']).first()
        db.session.delete(update)
        db.session.commit()
        return data

class deleteprogressreport(Resource):
#    @token_required
    def post(current_user):
        data = request.get_json()
        update = Progress_report.query.filter_by(datestamp=data['datestamp']).first()
        db.session.delete(update)
        db.session.commit()





