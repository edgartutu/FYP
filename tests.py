import unittest
from flask_testing import TestCase
from fyp import app
from project import  db
import json
class BaseTestCase(TestCase):

    def create_app(self):
        app.config.from_object('config.TestConfig')
        return app

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

        
class TestDepartments(BaseTestCase):
   
    def test_get_department_objects(self):
        r = self.client.get('http://localhost:5000/students',content_type='text')
        self.assertEqual(r.status_code, 200)
        
    def test_post_department_creation(self):
        tester = app.test_client(self)
        student={'name':'mutawe','school':'school','program':'program'}
        r = tester .post('http://localhost:5000/department/<string:name>/<string:school>/<string:program>',data=json.dumps(student))
        self.assertEqual(r.status_code, 200)  
        
if __name__ == '__main__':
    unittest.main()
