from project import app, db
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for
from flask_login import login_user,login_required, logout_user
from .forms import LoginForm,ProposalForm,ProjectForm,Proposal_comment_Form
import functools
from project import db, login_manager
from werkzeug.utils import secure_filename
import os
import datetime
from flask_login import login_user,login_required,logout_user
api = Api(app)



class Login(Resource):
    @staticmethod
    @login_required
    def post():
        error=None
        form = LoginForm(request.form)
        try:
            email, password = request.json.get('email').strip(), request.json.get('password').strip()
            print(email , password)
        except Exception as why:
            logging.info("reg_no or password is wrong. " + str(why))
            flash ('status: invalid input.')
        if email is None or password is None:
            flash ('status: user information is none.') 
        
        if request.method =='POST':
            if form.validate_on_submit():
                admin = Admin.query.filter_by(email=email, password=password).first()
                if admin is None:
                    flash ('status: user doesnt exist.')
                elif admin is not None and check_password_hash(
                    user.password, request.form['password']):
                    login_user(admin)
                    flash('You were logged in.')
##                    return redirect(url_for())
                else:
                    error = 'Invalid email or password'
        return render_template('login.html',form=form,error=error)

class Logout(Resource):
    @staticmethod
    @login_required
    def post():
        logout_user()
        flash('You were logged out. ')
##        return redirect(url_for(''))

class ApproveProject(Resource):
    @staticmethod
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
class PostProject(Resource):
    @staticmethod
    def post():
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

                
class PendingProposal(Resource):
    @staticmethod
    def get():
        students = Proposal.query.filter_by(status='pending').all()
        return students

    
class ProposalComment(Resource):
    @staticmethod
    def proposal_comment():
        form = Proposal_comment_Form(request.form)
        Proposal.comment = request.form['comment']
        db.session.commit()
        
