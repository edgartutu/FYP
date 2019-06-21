from project import app, db
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for
from flask_login import login_user,login_required, logout_user
from .forms import LoginForm,RegisterForm,Proposal_submittion_Form
from project.models import User
from project import db, login_manager
from werkzeug.utils import secure_filename
import os
import functools
from flask_login import login_user,login_required,logout_user
api = Api(app)


class Register(Resource):
    @staticmethod
    
    def post():
        form = RegisterForm()
        try:
            reg_no,email, password = request.json.get('reg_no').strip(), request.json.get('email').strip(),request.json.get('password').strip()
        except Exception as why:
            # Log input strip or etc. errors.
            logging.info("Username, password or email is wrong. " + str(why))
            flash('status:invalid input')
        if reg_no is None or password is None :
            flash ('status:field non')
        if form.validate_on_submit():
            user = User(email=form.email.data,reg_no=form.reg_no.data,password=form.password.data)
            if user is not None:
                flash ('status:user exist')
            # Create a new user.
            db.session.add(user)
            db.session.commit()
            flash('status registration completed.')
##            return redirect(url_for())


class Login(Resource):
    @staticmethod
    @login_required
    def post():
        error=None
        form = LoginForm(request.form)
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
                user = User.query.filter_by(reg_no=reg_no, password=password).first()
                if user is None:
                    flash ('status: user doesnt exist.')
                elif user is not None and check_password_hash(
                    user.password, request.form['password']):
                    login_user(user)
                    flash('You were logged in.')
##                    return redirect(url_for())
                else:
                    error = 'Invalid registration number or password'
        return render_template('login.html',form=form,error=error)


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
    
    def get():
        project = Project.query.all()
        return project

    
class PostProjects(Resource):
    
    def post():
        form = Proposal_submittion_Form(request.form)
        status = 'pending'
        supervisor = 'None'
        email = 'None'
        if request.method == 'POST':
            ## check if the post request has a file
            if 'file' not in request.files:
                flash('No file')
               ## return redirect(request.url)
            file = request.files['file']
            ## if user does not select file, browsr also
            ## submit an empty part without filename
            if file.filename == '':
                flash('No file selected')
                ## return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                p_upload = Proposal(request.form['title'],request.form['reg_no'],request.form['problem_statment'],
                                    request.form['abstract'],filename,request.form['student'],status,supervisor,email)
                db.session.add(p_upload)
                db.session.commmit()
                flash('File Uploaded')

                
class ViewPrjects(Resource):
    
    def get(reg_no):
        error = None
        project = Proposal.query.filter_by(reg_no=reg_no).all()
        rejected = Rejected_Proposal.query.filter_by(reg_no=reg_no).all()
        if project and rejected == None:
            flash("Proposal Not submitted")
        else:
            ## Checkout if this works
            return project,rejected
        


    
        
