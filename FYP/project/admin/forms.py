from flask_wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class LoginForm(Form):
    email = TextField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class ProposalForm(Form):
    ## Make status a drop down menu
    status = TextField('Approval',validators=[DataRequired()])
    supervisor = TextField('Supervisor',validators=[DataRequired()])
    email = TextField('Email',validators=[DataRequired()])
    comment = TextField('Comment',validators=[DataRequired()])

class ProjectForm(Form):
    title = TextField('Approval',validators=[DataRequired()])
    comments =  = TextField('Comment',validators=[DataRequired()])

class Proposal_comment_Form(Form):
    comment = TextField('Comment on project',validators=[DataRequired()])
