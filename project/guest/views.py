from project import app, db
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for
from flask_login import login_user,login_required, logout_user
from .forms import LoginForm
from project.models import User
from project import db, login_manager
import functools
from flask_login import login_user,login_required,logout_user
import logging



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
                guest = Guest.query.filter_by(email=email, password=password).first()
                if guest is None:
                    flash ('status: user doesnt exist.')
                elif guest is not None and check_password_hash(
                    user.password, request.form['password']):
                    login_user(guest)
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

class PostProject(Resource):
    @staticmethod
    def post(title,comments,report_uploadfile,date_submit):
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
    @staticmethod
    
    def get():
        project = Proposal.query.all()
        ## will need to iterate through the recode project like the for loop
        return project

        


        

        
