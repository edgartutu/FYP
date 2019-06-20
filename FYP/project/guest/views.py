from project import app, db
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for
from flask.ext.login import login_user,login_required, logout_user
from .forms import LoginForm
from project.models import User, bcrypt
from project import db, login_manager
import functools

class Guest():
    def login():
        error = None
        form = LoginForm(request.form)
        if request.method == 'POST':
            if form.validate_on_submit():
                admin = Guest.query.filter_by(email=request.form['email']).first()
                if admin is not None and bcrypt.check_password_hash(
                    admin.password,request.form['password']):
                    login_user(admin)
                    flash('Logged in as Guest')
##                    return redirect(url_for())

                else:
                    error = 'Invalid Email or password'
##            return render_template('Admin.html',form=form,error=error)

    def logout():
        logout_user()
        flash('You were logged out. ')
##        return redirect(url_for(''))

    def assigned_proposal(email):
        project = Proposal.query.filter_by(email=email).all()
        ## will i need to iterate through the recode project like the for loop
        return project

        


        

        
