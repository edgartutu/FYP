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


class Admin(db.Model, UserMixin):
    email = db.Column(db.String(64), primary_key=True, unique=True, index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, email, password):
        self.email = email
        self.password_hash = generate_password_hash(password)

class Guest(db.Model, UserMixin):
    email = db.Column(db.String(64), primary_key=True, unique=True, index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, email, password):
        self.email = email
        self.password_hash = generate_password_hash(password)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    reg_no = db.Column(db.String(25), primary_key=True, unique=True, index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, email, password, reg_no):
        self.reg_no = reg_no
        self.password_hash = generate_password_hash(password)

    def __repr__(self):
        if self.student_n0:
            return '{} /n {} /n {}'.format(self.reg_no, self.student_no.project, self.student_no.supervisor,
                                           self.student_no.date_submit)


class Project(db.Model, UserMixin):
    __tablename__ = 'projects'
    title = db.Column(db.String(500),primary_key=True)
##    reg_no = db.Column(db.String(25), primary_key=True, unique=True, index=True)
    

    report_uploadfile = db.Column(db.LargeBinary)
    comments = db.Column(db.String(500))
    date_submit = db.Column(db.DateTime)

    def __init__(self, title, description, proposal, report_uploadfile, supervisor, student_regno, comments,
                 date_submit):
        self.title = title
##        self.student_regno = student_regno
        self.report_uploadfile = report_uploadfile
        self.supervisor = supervisor
        self.comments = comments
        self.date_submit = date_submit

    def __repr__(self):
        return '{} /n {} /n {} /n {} /n {}'.format(self.project, self.project_proposal, self.supervisor,
                                                   self.date_submit, self.student_regno)


class Proposal(db.Model, UserMixin):
    title=db.Column(db.String(100))
    reg_no = db.Column(db.String(25), primary_key=True, unique=True, index=True)
    problem_statement = db.Column(db.String(1000))
    abstract = db.Column(db.String(1000))
    proposal_uploadfile = db.Column(db.LargeBinary)
    student = db.Column(db.String(500))
    status = db.Column(db.string(50))
    supervisor = db.Column(db.String(120))
    email = db.Column(db.String(500))
    comment = db.Column(db.String(500))
    ## status of the project  

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

    def json():
        return {'title':self.title,'problem_statement':self.problem_statement, 'abstract':self.abstract,
                'proposal_uploadfile':self.proposal_uploadfile,
                'student':self.student, 'student_no':self.student_no}

class Rejected_Proposal(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, unique=True, index=True)
    title=db.Column(db.String(100))
    reg_no = db.Column(db.String(25))
    problem_statement = db.Column(db.String(1000))
    abstract = db.Column(db.String(1000))
    proposal_uploadfile = db.Column(db.LargeBinary)
    student = db.Column(db.String(500))
    status = db.Column(db.string(50))
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

    def json():
        return {'title':self.title,'problem_statement':self.problem_statement, 'abstract':self.abstract,
                'proposal_uploadfile':self.proposal_uploadfile,
                'student':self.student, 'student_no':self.student_no}


db.create_all()