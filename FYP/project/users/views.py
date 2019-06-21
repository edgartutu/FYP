from project import app, db
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for
from flask.ext.login import login_user,login_required, logout_user
from .forms import LoginForm,Proposal_submittion_Form
from project.models import User, bcrypt
from project import db, login_manager
from werkzeug.utils import secure_filename
import os
import functools
api = Api(app)

class Users(Resource):
    def login ():
        error = None
        form = LoginForm(request.form)
        if request.method =='POST':
            if form.validate_on_submit():
                user = User.query.filter_by(reg_no=request.form['reg_n0']).first()
                if user is not None and bcrypt.check_password_hash(
                    user.password, request.form['password']):
                    login_user(user)
                    flash('You were logged in.')
##                    return redirect(url_for())
                else:
                    error = 'Invalid registration number or password'
        return render_template('login.html',form=form,error=error)    
    
    def logout():
        logout_user()
        flash('You were logged out.')
##        return redirect(url_for(''))

    def projects():
        project = Project.query.all()
        return project

    def submit_projects():
        form = Proposal_submittion_Form(request.form)
        status = 'pending'
        supervisor = 'None'
        email = 'None

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

    def view_project(reg_no):
        error = None
        project = Proposal.query.filter_by(reg_no=reg_no).all()
        rejected = Rejected_Proposal.query.filter_by(reg_no=reg_no).all()
        
        if project and rejected == None:
            flash("Proposal Not submitted")

        else:
            ## Checkout if this works
            return project,rejected
        


    
        
