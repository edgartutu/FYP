from flask_wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class LoginForm(Form):
    reg_n0 = TextField('registration n0', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class Proposal_submittion_Form(Form):
    title = TextField('Title',validators=[DataRequired()])
    reg_no = TextField('Registration Number',validators=[DataRequired()])
    problem_statment = TextField('Problem Statment',validators=[DataRequired()])
    abstract = TextField('Abstract',validators=[DataRequired()])
    student = TextField('Student',validators=[DataRequired()])
