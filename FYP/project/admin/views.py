from project import app, db
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for
from flask.ext.login import login_user,login_required, logout_user
from .forms import LoginForm,ProposalForm,ProjectForm,Proposal_comment_Form
from project.models import User, bcrypt 
import functools
from project import db, login_manager
from werkzeug.utils import secure_filename
import os
import datetime
api = Api(app)

class Admin(Resource):
    def login():
        error = None
        form = LoginForm(request.form)
        if request.method == 'POST':
            if form.validate_on_submit():
                admin = Admin.query.filter_by(email=request.form['email']).first()
                if admin is not None and bcrypt.check_password_hash(
                    admin.password,request.form['password']):
                    login_user(admin)
                    flash('Logged in as Administrator')
##                    return redirect(url_for())

                else:
                    error = 'Invalid Email or password'
##            return render_template('Admin.html',form=form,error=error)

    def logout():
        logout_user()
        flash('You were logged out. ')
##        return redirect(url_for(''))

    def proposals(reg_no):
        ##error = None
        student = Proposal.query.filter_by(reg_no=reg_no).all()
        if student is not None:
            Proposal.json()
            form = ProposalForm(request.form)
            
            if status == 'Approved':
                Proposal.status = request.form['status']
                Proposal.supervisor = request.form['supervisor']
                Proposal.email = request.form['email']
                proposal.comment = request.form['comment']

                db.session.commit()

            elif status == 'Rejected':
##                old_post=Proposal()
##                new_post= Rejected_Proposal()
##                moved_post=(Proposal.delete().where(old_post.reg_no=reg_no))
                
                rejected = Proposal.query.filter_by(reg_no=reg_no).first()
                new_data = []
                for row in rejected:
                    title = row[0]
                    reg_no = row[1]
                    problem_statment = row[2]
                    abstact = row[3]
                    proposal_uploadfile = row[4]
                    student = row[5]
                    status = 'Rejected'
                    supervisor = 'None'
                    email = 'None'
                    cmmt = comment

                    insert = Rejected_Proposal(title,reg_no,problem_statment,abstact,proposal_uploadfile,student,status,supervisor,email,comment)

                db.session.add(insert)
                db.session.delete(rejected)
                db.session.commit()

            else:
                flash('Error: Not successful')

        else:
            flash('Students proposal doesnt exist')

    def project():
        form = ProjectForm(request.form)
        ## formate date
        date_submit = datetime.datetime.today()
        ## report = TextField('Upload File',validators=[DataRequired()])
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
                
                ## return redirect(url_for('uploaded_file',filename=filename))
                fln = Project(request.form['title'],filename,request.form['comments'],date_submit)
                db.session.add(fln)
                db.session.commit()
                flash('File Uploaded')

    def unapproved_proposals():
        students = Proposal.query.filter_by(status='pending').all()
        return students

    def proposal_comment():
        form = Proposal_comment_Form(request.form)
        Proposal.comment = request.form['comment']
        db.session.commit()
        
