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




        

api.add_resource(Departments, '/department/<string:name>/<string:school>/<string:program>',endpoint='department')
api.add_resource(Departments, '/department/delete/<string:name>',endpoint='department-delete')
api.add_resource(AllnamesDepartments, '/students')



if __name__ == '__main__':
    app.run(debug=True)
