from project import app, db
from flask import render_template, redirect, request, url_for, flash, abort
from flask_login import login_user, login_required, logout_user
from project.models import User, Admin, Proposal, Department
from flask_restful import Resource, Api
from flask_jwt import JWT, jwt_required

api = Api(app)


class Proposal(Resource):
    def get(self, name, school, program):
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

    def delete(self, name, school, program):
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
