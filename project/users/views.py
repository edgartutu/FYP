from project import app, db
from project.models import User, Admin, Proposal, Department,Project,Rejected_Proposal
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
api = Api(app)


class Register(Resource):
    @staticmethod
    
    def post(email,reg_no,password,confirm_password):
        
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
                user = User(email=form.email.data,reg_no=form.reg_no.data,password=form.password.data)
                if user is not None:
                    flash ('status:user exist')
                # Create a new user.
                db.session.add(user)
                db.session.commit()
                flash('status registration completed.')
        else:
            flash('passwords dont match!!!!!')
    ##            return redirect(url_for())


class Login(Resource):
##    @staticmethod
##    @login_required
    def post(reg_no,password):
        error=None
        form = LoginForm()
        try:
            reg_no, password = request.json.get('reg_no').strip(), request.json.get('password').strip()
            print(reg_no , password)
        except Exception as why:
            logging.info("reg_no or password is wrong. " + str(why))
            flash ('status: invalid input.')
        if reg_no is None or password is None:
            flash ('status: user information is none.') 
        
        if request.method =='POST':
            if form.validate_on_submit():
                user = User.query.filter_by(reg_no=form.reg_no.data).first()
                if user is None:
                    flash ('status: user doesnt exist.')
                elif user is not None and user.check_password(form.password.data):
                    login_user(user)
                    flash('You were logged in.')
##                    return redirect(url_for())
                else:
                    error = 'Invalid registration number or password'
##        return render_template('try.html',form=form,error=error)



class Logout(Resource):
    @staticmethod
    @login_required
    def post():
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
    
    def get(self):
        project = Project.query.all()
        return project


class PostProjects(Resource):
    def __init__(self):
        pass
    
    def get(self,status,supervisor,email,title,reg_no, problem_statment,abstract,student_pair):
        header = {'Content-Type':'text/html'}
        
    
##        form = Proposal_submittion_Form()
        
        status = 'pending'
        supervisor = 'None'
        email = 'None'
        comment = 'None'
##        title=form.title.data
##        reg_no=form.reg_no.data
##        problem_statment=form.problem_statment.data
##        abstract=form.abstract.data
##        student=form.student.data
        
        if request.method == 'POST':

            if 'file' not in request.files:
                flash('No file')
              
            file = request.files['inputfile']
            ''' add validation'''
            
            if file.filename == '':
                flash('No file selected')
                ## return redirect(request.url)
            elif file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                return filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            p_upload = Proposal(title=title,reg_no=reg_no,problem_statment=problem_statment,abstract=abstract,proposal_uploadfile=file.read(),
                                student_pair=student_pair,status=status,supervisor=supervisor,email=email,comment=comment)
            db.session.add(p_upload)
            db.session.commmit()
            return p_upload
            flash('File Uploaded')

##        return make_response(render_template('try.html',form=form))

                
class ViewPrjects(Resource):
    
    def get(reg_no):
        error = None
        project = Proposal.query.filter_by(reg_no=str(reg_no)).first()
        rejected = Rejected_Proposal.query.filter_by(reg_no=str(reg_no)).all()
        if project and rejected == None:
            flash("Proposal Not submitted")
        else:
            ## Checkout if this works
            return project
        


    
        
