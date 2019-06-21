from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,TextField,validators
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class LoginForm(FlaskForm):
    reg_n0 = TextField('registration n0', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log in')

class Proposal_submittion_Form(FlaskForm):
    title = TextField('Title',validators=[DataRequired()])
    reg_no = TextField('Registration Number',validators=[DataRequired()])
    problem_statment = TextField('Problem Statment',validators=[DataRequired()])
    abstract = TextField('Abstract',validators=[DataRequired()])
    student = TextField('Student',validators=[DataRequired()])
    submit = SubmitField('Submit')

class RegisterForm(FlaskForm):
    reg_no = TextField('registration n0', validators=[DataRequired()])
    email = EmailField('Email address', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    pass_confirm=PasswordField('Confirm Password',validators=[DataRequired()])
    submit=SubmitField('Register!')
