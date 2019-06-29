# set up  db in __init__.py under my projects folder

from project import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin


class Department(db.Model, UserMixin):
    name = db.Column(db.String(64), primary_key=True)
    school = db.Column(db.String(128))
    program = db.Column(db.String(128))

    def __init__(self, name, school, program):
        self.name = name
        self.school = school
        self.program = program

    def json(self):
        return {'name': self.name, 'school': self.school, 'program': self.program}


class Program(db.Model, UserMixin):
    name = db.Column(db.String(64), primary_key=True)
    student = db.Column(db.String(128))

    def __init__(self, name, student):
        self.name = name
        self.student = student
        
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class Admin(db.Model, UserMixin):
    email = db.Column(db.String(64), primary_key=True, unique=True, index=True)
    publicID = db.Column(db.String(100))
    password = db.Column(db.String(128))


    def __init__(self, email, password):
        self.email = email
        self.password_hash = generate_password_hash(password)

    def check_password(self,password):     
        return check_password_hash(self.password_hash,password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class Guest(db.Model, UserMixin):
    email = db.Column(db.String(64), primary_key=True, unique=True, index=True)
    publicID = db.Column(db.String(100))
    password_hash = db.Column(db.String(128))

    def __init__(self, email, password):
        self.email = email
        self.password_hash = generate_password_hash(password)

    def check_password(self,password):
        return check_password_hash(self.password_hash,password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

    
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    reg_no = db.Column(db.String(25), primary_key=True, unique=True, index=True)
    publicID = db.Column(db.String(100))
    email=db.Column(db.String(30))
    password_hash = db.Column(db.String(128))

    def __init__(self, email, password, reg_no):
        self.reg_no = reg_no
        self.email=email
        self.password_hash = generate_password_hash(password)

    def check_password(self,password):
        return check_password_hash(self.password_hash,password)

class Progress_report(db.Model,UserMixin):
    __tablename__='progress_reports'
    id = db.Column(db.Integer(),primary_key=True)
    reg_no = db.Column(db.String(25))
##    files = db.Column(db.LargeBinary)
    '''change this back to large binary'''
    files = db.Column(db.String(100))

    def __init__(self,reg_no,files):
        self.reg_no = reg_no
        self.files = files

class Previous_topic(db.Model,UserMixin):
    __tablename__='previous_topics'
    id = db.Column(db.Integer(),primary_key=True)
    title = db.Column(db.String(25))
    abstract = db.Column(db.String(3000))
    year = db.Column(db.String(15))

    def __init__(self,title,abstract,year):
        self.title = title
        self.abstract = abstract
        self.year = year

class Progress_comment(db.Model,UserMixin):
    __tablename__='comment'
    id = db.Column(db.Integer(),primary_key=True)
    reg_no = db.Column(db.String(25))
    body = db.Column(db.String(3000))

    def __init__(self,reg_no,body):
        self.reg_no = reg_no
        self.body = body
    
class Project(db.Model, UserMixin):
    __tablename__ = 'projects'
    title = db.Column(db.String(500),primary_key=True)
##    reg_no = db.Column(db.String(25), primary_key=True, unique=True, index=True)
##    report_uploadfile = db.Column(db.LargeBinary)
    comments = db.Column(db.String(500))
    date_submit = db.Column(db.String(50))

    def __init__(self, title,comments,
                 date_submit):
        self.title = title
##        self.student_regno = student_regno
        self.comments = comments
        self.date_submit = date_submit

    def json(self):
        return {'title':self.title, 'comments':self.comments,
                                                  'date_submit': self.date_submit}


class Proposal(db.Model, UserMixin):
    
    reg_no = db.Column(db.String(25), primary_key=True, unique=True, index=True)
    title=db.Column(db.String(100))
    problem_statement = db.Column(db.String(1000))
    abstract = db.Column(db.String(5000))
    proposal_uploadfile = db.Column(db.String(1000))
    student_pair = db.Column(db.String(500))
    status = db.Column(db.String(50))
    supervisor = db.Column(db.String(120))
    email = db.Column(db.String(500))
    comment = db.Column(db.String(500))
    ## status of the project  

    def __init__(self,problem_statement,reg_no, abstract, proposal_uploadfile, student_pair,title,status,supervisor,email,comment):
        self.title = title
        self.reg_no = reg_no
        self.problem_statement = problem_statement
        self.abstract = abstract
        self.proposal_uploadfile = proposal_uploadfile
        self.student_pair = student_pair
        self.status = status
        self.supervisor = supervisor
        self.email = email
        self.comment = comment

    def json(self):
        return {'reg_no':self.reg_no,'title':self.title,'problem_statement':self.problem_statement, 'abstract':self.abstract,
                'proposal_uploadfile':self.proposal_uploadfile,
                'student':self.student_pair, 'supervisor':self.supervisor,'status':self.status,'commet':self.comment}

class Rejected_Proposal(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, unique=True, index=True)
    title=db.Column(db.String(100))
    reg_no = db.Column(db.String(25))
    problem_statement = db.Column(db.String(1000))
    abstract = db.Column(db.String(1000))
    proposal_uploadfile = db.Column(db.LargeBinary)
    student = db.Column(db.String(500))
    status = db.Column(db.String(50))
    supervisor = db.Column(db.String(120))
    email = db.Column(db.String(500))
    comment = db.Column(db.String(500)) 

    def __init__(self, problem_statement, abstract, proposal_uploadfile, student, student_no,title,status,supervisor,email,comment):
        self.title = title
        self.problem_statement = problem_statement
        self.abstract = abstract
        self.proposal_uploadfile = proposal_uploadfile
        self.student = student
        self.student_no = student_no
        self.status = status
        self.supervisor = supervisor
        self.email = email
        self.comment = comment

    def json(self):
        return {'title':self.title,'problem_statement':self.problem_statement, 'abstract':self.abstract,
                'proposal_uploadfile':self.proposal_uploadfile,
                'student':self.student, 'student_no':self.student_no}


db.create_all()
