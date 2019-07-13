from project import app, db
from project.models import User, Admin, Proposal, Department,Project,Rejected_Proposal,Guest,Progress_report
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for,make_response
from flask_login import login_user,login_required, logout_user
from .forms import LoginForm,ProposalForm,ProjectForm,Proposal_comment_Form
import functools
from project import db, login_manager
from werkzeug.utils import secure_filename
import os
import datetime
from flask_login import login_user,login_required,logout_user
from flask import jsonify
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
from functools import wraps
import json
import random

api = Api(app)

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
##                admin = Admin.query.filter_by(email=email, password=password).first()
##                if admin is None:
##                    flash ('status: user doesnt exist.')
##                elif admin is not None and check_password_hash(
##                    user.password, request.form['password']):
##                    login_user(admin)
##                    flash('You were logged in.')
####                    return redirect(url_for())
##                else:
##                    error = 'Invalid email or password'
##        return make_response(render_template('adminlogin.html',form=form))
##        return render_template('login.html',form=form,error=error)


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
            current_user = Admin.query.filter_by(publicID=data['public_id']).first()
            
        except:
            return make_response('Invalid Token',401,{'www-Authenticate':'Invalid Token"'})
        return f(current_user,*args,**kwargs)
    return decorated
    
class Login(Resource):
    def get(self):
        auth = request.get_json()
        '''checking if authorization information is complete'''
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify1',401,{'www-Authenticate':'Basic realm-"login required!"'})        
        admin = Admin.query.filter_by(email=auth.username).first()
        
        if not admin:
            return make_response('Could not verify2',401,{'www-Authenticate':'Basic realm-"login required!"'})       

        if admin.password == auth.password:
            token = jwt.encode({'public_id':admin.publicID,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=60)},app.config['SECRET_KEY'])
            return jsonify({'token':token.decode('UTF-8')})
        return make_response('Could not verify3',401,{'www-Authenticate':'Basic realm-"login required!"'})

class Logout(Resource):
#    @token_required
##    @staticmethod
    @login_required
    def post(self,current_user):
        logout_user()
        flash('You were logged out. ')
##        return redirect(url_for(''))

class ResetPassword(Resource):
    def post(self):
        old_pass, new_pass = request.json.get('old_pass'), request.json.get('new_pass')
        user = Admin.query.filter_by(email=email).first()
        if user.password != old_pass:
            flash ('status: old password does not match.')
        user.password = new_pass
        db.session.commit()
        flash('status: password changed.')
##        return redirect(url_for())

        
class ApproveProject(Resource):
#    @token_required
##    @staticmethod
    def get(current_user):
        if Proposal.status =='Approved':
            aproved = Proposal.query.all()
            return [x for x in aproved]
        elif Proposal.status == 'Rejected':
            reject = Rejected_Proposal.query.all()
            return [x for x in rejected]      
##        return make_response(render_template('approveprojects.html',form=form))
    
    def post(current_user):
        data = request.get_json()
        student = Proposal.query.filter_by(reg_no=data["reg_no"]).first()
        
        if student is not None:
##            Proposal.json(self)
##            form = ProposalForm(request.form)
##            return student.json()
            
            status = data["status"]
            
            if status == "Approved":
                student.status = data["status"]
                student.supervisor = data["supervisor"]
                student.email = data["email"]
                student.comment = data["comment"]
                db.session.commit()
                return data
            elif status == 'Rejected':
                rejected = Proposal.query.filter_by(reg_no=data['reg_no']).first()
                new_data = []
                
                title = rejected.title
                reg_no = data['reg_no']
                problem_statment = rejected.problem_statement
                abstact = rejected.abstract
                proposal_uploadfile = rejected.proposal_uploadfile.encode('utf-8')
                student = rejected.student_pair
                status = 'Rejected'
                supervisor = 'None'
                email = 'None'
                comment = data['comment']
                insert = Rejected_Proposal(title,reg_no,problem_statment,abstact,proposal_uploadfile,student,status,supervisor,email,comment)
                db.session.add(insert)
                db.session.delete(rejected)
                db.session.commit()
                
            else:
##                flash('Error: Not successful')
                make_response('Could not verify7',401,{'www-Authenticate':'Basic realm-"login required!"'})
##                return student
        else:
            make_response('Could not verify2',401,{'www-Authenticate':'Basic realm-"login required!"'})
##            flash('Students proposal doesnt exist')
##        return make_response(render_template('approveproject.html',form=form))
         
class PostProject(Resource):
#    @token_required
    def post(current_user):
        data = request.get_json()
        p=str(datetime.date.today())
        fln = Project(title=data['title'] ,comments=data['comments'],date_submit=p)
        db.session.add(fln)
        db.session.commit()
        
    def delete(self,current_user):
        data = request.get_json()
        proj=Project.query.filter_by(title=data['title']).first()
        db.session.delete(proj)
        db.session.commit()
        return {'status':'succces'}

#    @token_required
    def put(self,current_user):
        data = request.get_json()
        proj=Project.query.filter_by(title=data['title']).first()
        proj.title=request.json.get('title',proj.title)
        proj.comments=request.json.get('comments',proj.comments)
        db.session.commit()
        return jsonify({'proj':proj})
        
class PendingProposal(Resource):
#    @token_required
    def get(self,current_user):
        students = Proposal.query.filter_by(status='pending')
        return [x.json() for x in students]

class ProposalComment(Resource):
#    @token_required
##    @staticmethod
    def post(self,current_user):
        data = request.get_json()
        comm = Proposal(comment=data['comment'])
        db.session.add(comm)
        db.session.commit()
        return comm.json()
##        
####        form = Proposal_comment_Form(request.form)
####        Proposal.comment = request.form['comment']
##        Proposal.comment=comment
##        db.session.commit()
class ApprovedProposal(Resource):
#   @token_required
   def get(current_user):
        students = Proposal.query.filter_by(status='Approved')
        return [x.json() for x in students]

class viewprojects(Resource):
    @token_required
    def get(current_user):
        students = Project.query.all()
        return [x.json() for x in students]

class viewrejected(Resource):
#    @token_required
##    @staticmethod
    def get(current_user):
        students = Rejected_Proposal.query.all()
        return [x.json() for x in students]

class allstudents(Resource):
#    @token_required
    def get(current_user):
        student = User.query.all()
        return [x.json() for x in student]

class allguest(Resource):
#    @token_required
    def get(current_user):
        guest = Guest.query.all()
        return [x.json() for x in guest]

class allprogressreports1(Resource):
##    @token_required
    def get(current_user):
        reports = Progress_report.query.all()
        return [x.json() for x in reports]

class progressreportquery(Resource):
#    @token_required
    def get(current_user):
        data = request.get_json()
        reg_no = data["reg_no"]
        report = Progress_report.query.filter_by(reg_no=reg_no)
        return [x.json() for x in report]

class proposalbysupervisor(Resource):
#    @token_required
    def get(current_user):
        data = request.get_json()
        email = data["email"]
        proposal = Proposal.query.filter_by(email=email)
        return [x.json() for x in proposal]

## add routes
class preprocessing(Resource):
#    @token_required
    def get(current_user):
        data = request.get_json()
        reg_no = data['reg_no']
        comment = data['comment']
        proposal = Proposal.query.filter_by(reg_no=reg_no).first()
        proposal.comment = 'Hello'
        db.session.commit()
        return data





