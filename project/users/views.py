from project import app, db
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for
from flask.ext.login import login_user,login_required, logout_user
from .forms import LoginForm
from project.models import User, bcrypt 
import functools
api = Api(app)

class Users(Resource):
    def login ():
        error = None
        form = LoginForm(request.form)
        if request.method =='POST':
            if form.validate_on_submit():
                user = User.query.filter_by(reg_no=request.form['reg_n0']).firt()
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


    def is_user(f):

        '''logic for the user'''

        

