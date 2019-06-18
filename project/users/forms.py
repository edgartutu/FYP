from flask_wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class LoginForm(Form):
    reg_n0 = TextField('registration n0', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
