from project import app, db
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api

api = Api(app)


class Proposal(Resource):
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

    def delete(self, name):
        dep = Department.query.filter_by(name=name)
        db.session.delete(dep)
        db.session.commit()


class Allnames(Resource):
    def get(self):
        dep = Department.query.all()
        return [x.json() for x in dep]


api.add_resource(Proposal, '/department/<string:name>/<string:school>/<string:program>')
api.add_resource(Allnames, '/students')

if __name__ == '__main__':
    app.run(debug=True)
