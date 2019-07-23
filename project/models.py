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
    name = db.Column(db.String(200))
    publicID = db.Column(db.String(100))
    password_hash = db.Column(db.String(128))

    def __init__(self, email, password,name):
        self.email = email
        self.name = name
        self.password_hash = generate_password_hash(password)

    def json(self):
        return {'name':self.name,'email':self.email,'password_hash':self.password_hash}
        

    def check_password(self,password):
        return check_password_hash(self.password_hash,password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

    
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    reg_no = db.Column(db.String(25), primary_key=True, unique=True, index=True)
    student1 = db.Column(db.String(100))
    reg_no2 = db.Column(db.String(100))
    student2 = db.Column(db.String(100))
    publicID = db.Column(db.String(100))
    email = db.Column(db.String(30))
    email2 = db.Column(db.String(100))
    course = db.Column(db.String(5))
    tel = db.Column(db.String(100))
    tel2 = db.Column(db.String(100))
    password_hash = db.Column(db.String(128))

    def __init__(self, email, password_hash, reg_no,student1,reg_no2,student2,email2,tel,tel2,course):
        self.reg_no = reg_no
        self.email=email
        self.password_hash = generate_password_hash(password_hash)
        self.student1=student1
        self.reg_no2=reg_no2
        self.student2=student2
        self.email2=email2
        self.tel=tel
        self.tel2=tel2
        self.course = course

    def json(self):
        return {'reg_no':self.reg_no,'student1':self.student1,'student2':self.student2,
                'reg_no2':self.reg_no2,'email': self.email,'email2': self.email2,'tel': self.tel,'tel2': self.tel2,
                'password_hash':password_hash,'course': self.course}
        
    def check_password(self,password_hash):
        return check_password_hash(self.password_hash,password_hash)

class Progress_report(db.Model, UserMixin):
    __tablename__='progress_reports'
    id = db.Column(db.Integer(),primary_key=True)
    reg_no = db.Column(db.String(25))
    supervisor_email = db.Column(db.String(25))
    comment = db.Column(db.String(200))
    files = db.Column(db.String(100))
    datestamp = db.Column(db.String(100))

    def __init__(self,reg_no,files,supervisor_email,datestamp,comment):
        self.reg_no = reg_no
        self.files = files
        self.supervisor_email=supervisor_email
        self.datestamp=datestamp
        self.comment = comment

    def json(self):
        return {'reg_no':self.reg_no,'files':self.files,'supervisor_email':self.supervisor_email,
                'datestamp': self.datestamp,'comment':self.comment}

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

    def json(self):
        return {'title':self.title, 'abstract':self.abstract, 'year': self.year}


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
    ref_no = db.Column(db.String(50),primary_key=True)
    title = db.Column(db.String(500))
    comments = db.Column(db.String(500))
    date_submit = db.Column(db.String(50))

    def __init__(self,ref_no, title,comments,date_submit):
        self.ref_no = ref_no
        self.title = title
##        self.student_regno = student_regno
        self.comments = comments
        self.date_submit = date_submit

    def json(self):
        return {'ref_no':self.ref_no,'title':self.title, 'comments':self.comments,'date_submit': self.date_submit}

class ExportApproved(db.Model, UserMixin):
    __tablename__ = 'ApprovedExports'
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(500))

    def __init__(self,name):
        self.name = name

    def json(self):
        return {"name":self.name}


class Proposal(db.Model, UserMixin):
    
    id = db.Column(db.String(15))
    reg_no = db.Column(db.String(25), primary_key=True, unique=True, index=True)
    student1=db.Column(db.String(100))
    reg_no2 = db.Column(db.String(500))
    student2 = db.Column(db.String(500))
    project_ref = db.Column(db.String(15))
    title=db.Column(db.String(100))
    problem_statement = db.Column(db.String(1000))
    methodology = db.Column(db.String(5000))
    proposal_uploadfile = db.Column(db.String(100))
    status = db.Column(db.String(50))
    supervisor = db.Column(db.String(120))
    email = db.Column(db.String(500))
    comment = db.Column(db.String(500))
    ## status of the project  

    def __init__(self,id,project_ref,problem_statement,reg_no, methodology, proposal_uploadfile,reg_no2,title,status,supervisor,email,comment,student1,student2):
        self.id = id
        self.title = title
        self.reg_no = reg_no
        self.project_ref = project_ref
        self.problem_statement = problem_statement
        self.methodology = methodology
        self.proposal_uploadfile = proposal_uploadfile
        self.reg_no2 = reg_no2
        self.status = status
        self.supervisor = supervisor
        self.email = email
        self.comment = comment
        self.student1 = student1
        self.student2 = student2

    def json(self):
        return {'id':self.id,'project_ref':self.project_ref,'reg_no':self.reg_no,'title':self.title,
                'problem_statement':self.problem_statement, 'methodology':self.methodology,
                'proposal_uploadfile':self.proposal_uploadfile,
                'reg_no2':self.reg_no2, 'supervisor':self.supervisor,'status':self.status,'commet':self.comment,
                'student1':self.student1,'student2':self.student2,'proposal_upload':self.proposal_uploadfile}

class Rejected_Proposal(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, unique=True, index=True)
    reg_no = db.Column(db.String(25))
    student1=db.Column(db.String(100))
    reg_no2 = db.Column(db.String(500))
    student2 = db.Column(db.String(500))
    title=db.Column(db.String(100))
    problem_statement = db.Column(db.String(1000))
    methodology = db.Column(db.String(5000))
    proposal_uploadfile = db.Column(db.String(100))
    status = db.Column(db.String(50))
    supervisor = db.Column(db.String(120))
    email = db.Column(db.String(500))
    comment = db.Column(db.String(500))
    ## status of the project  

    def __init__(self,problem_statement,reg_no, methodology, proposal_uploadfile,reg_no2,title,status,supervisor,email,comment,student1,student2):
        self.title = title
        self.reg_no = reg_no
        self.problem_statement = problem_statement
        self.methodology = methodology
        self.proposal_uploadfile = proposal_uploadfile
        self.reg_no2 = reg_no2
        self.status = status
        self.supervisor = supervisor
        self.email = email
        self.comment = comment
        self.student1 = student1
        self.student2 = student2

    def json(self):
        return {'reg_no':self.reg_no,'title':self.title,
                'problem_statement':self.problem_statement, 'methodology':self.methodology,
                'proposal_uploadfile':self.proposal_uploadfile,
                'reg_no2':self.reg_no2, 'supervisor':self.supervisor,'status':self.status,'commet':self.comment,
                'student1':self.student1,'student2':self.student2,'proposal_upload':self.proposal_uploadfile}


db.create_all()
