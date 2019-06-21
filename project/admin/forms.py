from flask_wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_wtf import FlaskForm

class LoginForm(FlaskForm):
    email = TextField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class ProposalForm(FlaskForm):
    ## Make status a drop down menu
    status = TextField('Approval',validators=[DataRequired()])
    supervisor = TextField('Supervisor',validators=[DataRequired()])
    email = TextField('Email',validators=[DataRequired()])
    comment = TextField('Comment',validators=[DataRequired()])

class ProjectForm(FlaskForm):
    title = TextField('Approval',validators=[DataRequired()])
    comments = TextField('Comment',validators=[DataRequired()])

class Proposal_comment_Form(FlaskForm):
    comment = TextField('Comment on project',validators=[DataRequired()])
