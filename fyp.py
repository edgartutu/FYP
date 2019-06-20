from project import app, db
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api
from flask import request

api = Api(app)


class Departments(Resource):
    def get(self, name):
        dep = Department.query.filter_by(name=name).first()
        if dep:
            return dep.json()
        else:
            return {'credentials': ' dont exist '}, 404

    def post(self, name, school, program):
        dep = Department(name=name, school=school, program=program)
        db.session.add(dep)
        db.session.commit()
        return dep.json()

    def delete(self,name):
        dep = Department.query.filter_by(name=name).first()
        db.session.delete(dep)
        db.session.commit()
        return {'status':'succces'}
        


class AllnamesDepartments(Resource):
    def get(self):
        dep = Department.query.all()
        return [x.json() for x in dep]



class Proposal(Resource):
    def get(self,title):
        pro=Proposal.query.filter_by(title=title)
        pro = False
        for x in pro:
            if tittle in pro:
                pro=True
        if True:
            return pro.json()
        else:
            return {'tittle': ' doesnt exist '}, 404

    def post(self,problem_statement,abstract,proposal_uploadfile,student,student_no):
        pro=Proposal(problem_statement=problem_statement, abstract=abstract,
                     proposal_uploadfile=proposal_uploadfile,
                     student=student, student_no=student_no)
        db.session.add(pro)
        db.session.commit()
        return pro.json()

    def put(self,title): 
        json_data = request.get_json(force=True)
        if not json_data:
               return {'message': 'No input data provided'}, 400
        data, errors = category_schema.load(json_data)
        if errors:
            return errors, 422
        category = Proposal.query.filter_by(title=data['title']).first()
        if not category:
            return {'message': 'Category does not exist'}, 400
        category.name = data['name']
        db.session.commit()
        result = category_schema.dump(category).data
        return { "status": 'success', 'data': result }, 204

    def delete(self,title):
        pro=Proposal.query.filter_by(title=title)
        pro = False
        for x in pro:
            if tittle in pro:
                pro=True
        if True:
            db.session.delete(pro)
            db.session.commit()
class AllProposals(Resource):

    def get():
        pro = Proposal.query.all()
        return [x.json() for x in pro]

class Project(Resource):

    def get(self,title):
        proj=Project.query.filter_by(title=title).first()
        proj = False
        for x in proj:
            if tittle in proj:
                proj=True
        if True:
            return proj.json()
        else:
            return {'tittle': ' doesnt exist '}, 404

    def post(self,title):
        proj=Project(title=title)
        db.session.add(proj)
        db.session.commit()
        return proj.json()

    def put(self,title):
        json_data = request.get_json(force=True)
        if not json_data:
               return {'message': 'No input data provided'}, 400
        data, errors = category_schema.load(json_data)
        if errors:
            return errors, 422
        category = Project.query.filter_by(title=data['title']).first()
        if not category:
            return {'message': 'Category does not exist'}, 400
        category.name = data['name']
        db.session.commit()
        result = category_schema.dump(category).data
        return { "status": 'success', 'data': result }, 204

    def delete(self,title):
        proj=Proposal.query.filter_by(title=title).first()
        proj = False
        for x in proj:
            if tittle in proj:
                proj=True
        if True:
            db.session.delete(proj)
            db.session.commit()
            return proj.json()

        

api.add_resource(Departments, '/department/<string:name>/<string:school>/<string:program>',endpoint='department')
api.add_resource(Departments, '/department/delete/<string:name>',endpoint='department-delete')
api.add_resource(AllnamesDepartments, '/students')
api.add_resource(Proposal,'/proposal')
api.add_resource(AllProposals,'/proposals')
api.add_resource(Project,'/projects')



if __name__ == '__main__':
    app.run(debug=True)
