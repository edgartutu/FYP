from flask_wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_wtf import FlaskForm

class LoginForm(FlaskForm):
    email = TextField('registration n0', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


