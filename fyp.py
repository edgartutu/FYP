
from project import app,db

from flask import render_template,redirect,request,url_for,flash,abort
from flask_login import login_user,login_required,logout_user

from project.models import User,Admin,Proposal

from flask_restful import Resource,Api
from flask_jwt import JWT,jwt_required

api=Api(app)



class Proposal(Resource):

    

    def get(self,name):
        
            
            

    def post(self,name):
        
            
             
    def delete(self,name):
        
            
		


class Allfiles(Resource):
	



api.add_resource()
api.add_resource()

if __name__ == '__main__':
    app.run(debug=True)


