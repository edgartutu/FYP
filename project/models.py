#set up  db in __init__.py under my projects folder




from project import db,login_manager
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin



##@login_manager.user_loader
##def load_user(user_id):
##	return User.query.get(user_id)


class Department(db.Model,UserMixin):
    
    name = db.Column(db.String(64),primary_key=True)
    
    school = db.Column(db.String(128))

    program = db.Column(db.String(128))

    def __init__(self,name,school,program):
        
        self.name=name
        
        self.school=school

        self.program=program

    def json(self):
        return {'name':self.name,'school':self.school,'program':self.program}   

        
        
class Program(db.Model,UserMixin):
    
    name = db.Column(db.String(64),primary_key=True)
    
    student = db.Column(db.String(128))

    def __init__(self,name,student):
        
        self.name=name
        
        self.student=student

        

class Admin(db.Model,UserMixin):
    
    email = db.Column(db.String(64),primary_key=True,unique=True,index=True)
    
    password_hash = db.Column(db.String(128))

    def __init__(self,email,password):
        
        self.email=email
        
        self.password_hash=generate_password_hash(password)

    


class User(db.Model,UserMixin):

    __tablename__='users'

    reg_no = db.Column(db.String(25),primary_key=True,unique=True,index=True)

    password_hash = db.Column(db.String(128))

##    student_no = db.relationship('Proposal', backref='student', lazy=True)

    def __init__(self,email,password):
        
        self.reg_no=reg_no
        
        self.password_hash=generate_password_hash(password)

    def __repr__(self):
        
        if self.student_n0:
                return '{} /n {} /n {}'.format(self.reg_no,self.student_no.project,self.student_no.supervisor,self.student_no.date_submit)
      

        


class Project(db.Model,UserMixin):

    __tablename__='projects'

    title = db.Column(db.String(500))

##    description = db.Column(db.String(500))
##
##    proposal = db.Column(db.String(2500))
    reg_no = db.Column(db.String(25),primary_key=True,unique=True,index=True)

##    student_regno = db.Column(db.String(25), db.ForeignKey('users.reg_no'),nullable=False)

    report_uploadfile=db.Column(db.LargeBinary)

    supervisor=db.Column(db.String(120))

    comments =db.Column(db.String(500))

    date_submit = db.Column(db.DateTime)

##    student_no = db.relationship('Proposal', backref='student', lazy=True)


    def __init__(self,title,description,proposal,report_uploadfile,supervisor,student_regno,comments,date_submit):

        self.title=title

        self.description=description

        self.proposal=proposal

        self.student_regno=student_regno

        self.report_uploadfile=report_uploadfile

        self.supervisor=supervisor

        self.comments =comments 

        self.date_submit=date_submit

       

    def __repr__(self):

        return '{} /n {} /n {} /n {} /n {}'.format(self.project,self.project_proposal,self.supervisor,self.date_submit,self.student_regno)

    
class Proposal(db.Model,UserMixin):

    reg_no = db.Column(db.String(25),primary_key=True,unique=True,index=True)

    problem_statement = db.Column(db.String(1000))

    abstract = db.Column(db.String(1000))

    proposal_uploadfile=db.Column(db.LargeBinary)

    student = db.Column(db.String(500))

##    student_regno = db.Column(db.String(25), db.ForeignKey('projects.reg_no'),nullable=False)

    

    def __init__(self,problem_statement,abstract,proposal_uploadfile,student,student_no):
        
        self.problem_statement=problem_statement

        self.abstract=abstract

        self.proposal_uploadfile=proposal_uploadfile

        self.student=student

        self.student_no=student_no
    
    
db.create_all()    

