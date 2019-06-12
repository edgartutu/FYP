
#set up  db in __init__.py under my projects folder




from project import db,login_manager
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin



##@login_manager.user_loader
##def load_user(user_id):
##	return User.query.get(user_id)


class Admin(db.Model,UserMixin):
    
    email = db.Column(db.String(64),unique=True,index=True)
    
    password_hash = db.Column(db.String(128))

    def __init__(self,email,password):
        
        self.email=email
        
        self.password_hash=generate_password_hash(password)

    


class User(db.Model,UserMixin):

    reg_no = db.Column(db.String(25),unique=True,index=True)

    password_hash = db.Column(db.String(128))

    student_no = db.relationship('Proposal', backref='student', lazy=True)

    def __init__(self,email,password):
        
        self.reg_no=reg_no
        
        self.password_hash=generate_password_hash(password)

    def __repr__(self):
        if self.student_n0:
                return '{} /n {} /n {}'.format(self.reg_no,self.student_no.project,self.student_no.supervisor,self.student_no.date_submit)
      

        


class Proposal(db.Model,UserMixin):

    project = db.Column(db.String(500))

    student_regno = db.Column(db.String(25), db.ForeignKey('User.reg_no'),nullable=False)

    project_proposal=db.Column(db.LargeBinary)

    supervisor=db.Column(db.String(120))

    date_submit = db.Column(db.DateTime)


    def __init__(self,project,project_proposal,supervisor,date_submit):

        self.project=project

        self.student_regno=student_regno

        self.project_proposal=project_proposal

        self.supervisor=supervisor

        self.date_submit=date_submit

    def __repr__(self):

        return '{} /n {} /n {} /n {} /n {}'.format(self.project,self.project_proposal,self.supervisor,self.date_submit,self.student_regno)

    
 

    
    

