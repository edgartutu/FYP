from project import app, db
from project.models import User, Admin, Proposal, Department,Project,Rejected_Proposal,Guest,Progress_report,ExportApproved
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for,make_response
from flask_login import login_user,login_required, logout_user
from .forms import LoginForm,ProposalForm,ProjectForm,Proposal_comment_Form
import functools
from project import db, login_manager
from werkzeug.utils import secure_filename
import os
import datetime
from flask_login import login_user,login_required,logout_user
from flask import jsonify
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
from functools import wraps
import json
import random
from flask import send_file, send_from_directory, safe_join, abort
import flask_excel as excel
import pyexcel
import uuid
import time


api = Api(app)

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
    
            return make_response('Invalid Token',401,{'www-Authenticate':'Invalid Token"'})
        try:
            
            data = jwt.decode(token,app.config['SECRET_KEY'])
            current_user = Admin.query.filter_by(publicID=data['public_id']).first()
            
        except:
            return make_response('Invalid Token',401,{'www-Authenticate':'Invalid Token"'})
        return f(current_user,*args,**kwargs)
    return decorated
    
class Login(Resource):
    def post(self):
        #auth = request.get_json()
        data = request.get_json()
        '''checking if authorization information is complete'''
        if not data or not data['username'] or not data['password']:
            return make_response('Could not verify1',401,{'www-Authenticate':'Basic realm-"login required!"'})
        admin = Admin.query.filter_by(email=data['username']).first()
        
        if not admin:
            return make_response('Could not verify2',401,{'www-Authenticate':'Basic realm-"login required!"'})       

        if admin.password == data['password']:
            token = jwt.encode({'public_id':admin.publicID,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=60)},app.config['SECRET_KEY'])
            return jsonify({'token':token.decode('UTF-8'),'username':admin.publicID})
        return make_response('Could not verify3',401,{'www-Authenticate':'Basic realm-"login required!"'})

class Logout(Resource):
#    @token_required
##    @staticmethod
    @login_required
    def post(self,current_user):
        logout_user()
        flash('You were logged out. ')
##        return redirect(url_for(''))

class ResetPassword(Resource):
    def post(self):
        old_pass, new_pass = request.json.get('old_pass'), request.json.get('new_pass')
        user = Admin.query.filter_by(email=email).first()
        if user.password != old_pass:
            flash ('status: old password does not match.')
        user.password = new_pass
        db.session.commit()
        flash('status: password changed.')
##        return redirect(url_for())

        
class ApproveProject(Resource):
#    @token_required
##    @staticmethod
    def get(current_user):
        if Proposal.status =='Approved':
            aproved = Proposal.query.all()
            return [x for x in aproved]
        elif Proposal.status == 'Rejected':
            reject = Rejected_Proposal.query.all()
            return [x for x in rejected]      
##        return make_response(render_template('approveprojects.html',form=form))
    
    def post(current_user):
        data = request.get_json()
        student = Proposal.query.filter_by(reg_no=data["reg_no"]).first()
        user = User.query.filter_by(reg_no=data["reg_no"]).first()
        
        if student is not None:
##            Proposal.json(self)
##            form = ProposalForm(request.form)
##            return student.json()
            
            status = data["status"]
            
            if status == "Approved":
                x = uuid.uuid4()
                y = str(x)
                course = user.course
                id = 'ECE-'+course+'-'+y[:8]
                student.id = id
                student.status = data["status"]
                student.supervisor = data["supervisor"]
                student.email = data["email"]
                student.comment = data["comment"]
                db.session.commit()
                return data

            elif status == 'Rejected':
                rejected = Proposal.query.filter_by(reg_no=data['reg_no']).first()
                new_data = []
                
                title = rejected.title
                reg_no = data['reg_no']
                reg_no2 = rejected.reg_no2
                problem_statment = rejected.problem_statement
                methodology = rejected.methodology
                proposal_uploadfile = rejected.proposal_uploadfile
                student1 = rejected.student1
                student2 = rejected.student2
                status = 'Rejected'
                supervisor = 'None'
                email = 'None'
                comment = data['comment']
                insert = Rejected_Proposal(title=title,reg_no=reg_no,reg_no2=reg_no2,problem_statement=problem_statment,
                                           methodology=methodology,proposal_uploadfile=proposal_uploadfile,
                                           student1=student1,student2=student2,status=status,
                                           supervisor=supervisor,email=email,comment=comment)
                db.session.add(insert)
                db.session.delete(rejected)
                db.session.commit()
                
            else:
##                flash('Error: Not successful')
                make_response('Could not verify7',401,{'www-Authenticate':'Basic realm-"login required!"'})
##                return student
        else:
            make_response('Could not verify2',401,{'www-Authenticate':'Basic realm-"login required!"'})
##            flash('Students proposal doesnt exist')
##        return make_response(render_template('approveproject.html',form=form))
         
class PostProject(Resource):
#    @token_required
    def post(current_user):
        data = request.get_json()
        x = uuid.uuid4()
        y = str(x)
        ref_id = 'ECE-'+'L-'+y[:8]
        p=str(datetime.date.today())
        fln = Project(ref_no=ref_id,title=data['title'] ,comments=data['comments'],date_submit=p)
        db.session.add(fln)
        db.session.commit()
        
    def delete(self,current_user):
        data = request.get_json()
        proj=Project.query.filter_by(title=data['title']).first()
        db.session.delete(proj)
        db.session.commit()
        return {'status':'success'}

    def put(self,current_user):
        data = request.get_json()
        proj=Project.query.filter_by(title=data['title']).first()
        proj.title=request.json.get('title',proj.title)
        proj.comments=request.json.get('comments',proj.comments)
        db.session.commit()
        return jsonify({'proj':proj})
        
class PendingProposal(Resource):
#    @token_required
    def get(current_user):
        students = Proposal.query.filter_by(status='pending')
        return [x.json() for x in students]

class pendingfiles(Resource):
#    @token_required
    def post(current_user):
        data = request.get_json()
        reg_no = data['reg_no']
        #reg_no = '3'
        students = Proposal.query.filter_by(reg_no=reg_no).first()
        name = students.json()["proposal_uploadfile"]
        #path1 = app.config['UPLOAD_FOLDER']
        #file = open(os.path.join(os.path.join(app.config['UPLOAD_FOLDER'],name)), 'rb')
        #return {"file":file}
        #return send_file(app.config['UPLOAD_FOLDER'],attachment_filename=name)
        try:
            return send_from_directory(app.config['UPLOAD_FOLDER'],filename=name, as_attachment=True)

        except FileNotFoundError:
            abort(404)

        #return os.path.join(os.path.join(app.config['UPLOAD_FOLDER'],name))

        #return send_file(app.config['UPLOAD_FOLDER'],attachment_filename=name)

class progressfiles(Resource):
#    @token_required
    def post(current_user):
        data = request.get_json()
        reg_no = data['reg_no']
        #reg_no = '3'
        students = Progress_report.query.filter_by(reg_no=reg_no).first()
        name = students.json()["files"]
        try:
            return send_from_directory(app.config['UPLOAD_FOLDER'],filename=name, as_attachment=True)

        except FileNotFoundError:
            abort(404)

class ProposalComment(Resource):
#    @token_required
##    @staticmethod
    def post(self,current_user):
        data = request.get_json()
        comm = Proposal(comment=data['comment'])
        db.session.add(comm)
        db.session.commit()
        return comm.json()
##        
####        form = Proposal_comment_Form(request.form)
####        Proposal.comment = request.form['comment']
##        Proposal.comment=comment
##        db.session.commit()

class ApprovedProposal(Resource):
#   @token_required
   def get(current_user):
        students = Proposal.query.filter_by(status='Approved')
        return [x.json() for x in students]

class viewprojects(Resource):
 #   @token_required
    def get(current_user):
        students = Project.query.all()
        return [x.json() for x in students]

class viewrejected(Resource):
#    @token_required
##    @staticmethod
    def get(current_user):
        students = Rejected_Proposal.query.all()
        return [x.json() for x in students]

class allstudents(Resource):
#    @token_required
    def get(current_user):
        student = User.query.all()
        return [x.json() for x in student]

class allguest(Resource):
#    @token_required
    def get(current_user):
        guest = Guest.query.all()
        return [x.json() for x in guest]

class allprogressreports1(Resource):
##    @token_required
    def get(current_user):
        reports = Progress_report.query.all()
        return [x.json() for x in reports]

class progressreportquery(Resource):
#    @token_required
    def get(current_user):
        data = request.get_json()
        reg_no = data["reg_no"]
        report = Progress_report.query.filter_by(reg_no=reg_no)
        return [x.json() for x in report]

class proposalbysupervisor(Resource):
#    @token_required
    def get(current_user):
        data = request.get_json()
        email = data["email"]
        proposal = Proposal.query.filter_by(email=email)
        return [x.json() for x in proposal]

## add routes
class preprocessing(Resource):
#    @token_required
    def get(current_user):
        data = request.get_json()
        reg_no = data['reg_no']
        comment = data['comment']
        proposal = Proposal.query.filter_by(reg_no=reg_no).first()
        proposal.comment = comment
        db.session.commit()
        return data

class proposaltracker(Resource):
#    @token_required
    def get(current_user):
        proposals = db.session.query(Proposal).count()
        users = db.session.query(User).count()
        try:
            percentage = (proposals/users)*100
            return percentage
        except Exception:
            return 0

class approvedtracker(Resource):
#    @token_required
    def get(current_user):
        proposals = db.session.query(Proposal).filter_by(status="Approved").count()
        users = db.session.query(User).count()
        try:
            percentage = (proposals/users)*100
            return percentage
        except Exception:
            return 0

class rejectedtracker(Resource):
#    @token_required
    def get(current_user):
        proposals = db.session.query(Rejected_Proposal).count()
        users = db.session.query(User).count()
        try:
            percentage = (proposals/users)*100
            return percentage
        except Exception:
            return 0

class pendingtracker(Resource):
#    @token_required
    def get(current_user):
        proposals = db.session.query(Proposal).filter_by(status="pending").count()
        users = db.session.query(User).count()
        try:
            percentage = (proposals/users)*100
            return percentage
        except Exception:
            return 0

class excelexport1(Resource):
#    @token_required
    def post(current_user):
        query_sets = Proposal.query.filter_by(status="Approved")
        autoGenFileName = uuid.uuid4()
        filename1 = str(autoGenFileName)+".xls"
        #filename1 = "ApprovedStudentsExport.xls"
        dictionary1 = [x.json() for x in query_sets]
        try:

            pyexcel.save_as(records=dictionary1, dest_file_name=os.path.join(app.config['EXCEL_FOLDER'],filename1))
            #download(filename1)
            return send_from_directory(app.config['EXCEL_FOLDER'],filename=filename1, as_attachment=True)

        except FileNotFoundError:
            abort(404)

#def download(name):
#    return send_from_directory(app.config['EXCEL_FOLDER'],filename=name, as_attachment=True)

class AllProposals(Resource):
##    @token_required
##    @staticmethod
    def get(current_user):
        students = Proposal.query.all()
        return [x.json() for x in students]

