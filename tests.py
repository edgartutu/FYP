import unittest
from flask_testing import TestCase
from fyp import app
from project import  db
import json
import os
from flask_jwt import JWT, jwt_required, current_identity
from json.decoder import JSONDecoder
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

    def test_app_is_testing(self):
        '''test app'''
        self.assertFalse(app.config['SECRET_KEY'] is 'mysecretkey')
        self.assertTrue(app.config['DEBUG'])
        basedir = os.path.abspath(os.path.dirname(__file__))
        self.assertTrue(
            app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///'+os.path.join(basedir,'data.sqlite')
        )
   
    def test_get_department_objects(self):
        '''get department data'''
        r = self.client.get('http://localhost:5000/students',content_type='text')
        self.assertEqual(r.status_code, 200)
        
    def test_post_department_creation(self):
        student={'name':'mutawe','school':'school','program':'program'}
        r = self.client.post('http://localhost:5000/department/<string:name>/<string:school>/<string:program>',data=json.dumps(student))
        self.assertEqual(r.status_code, 200)

    def post_user_data(self):
        ''' get the post data'''
        post_data = request.get_json()
        try:
            ''' fetch the user data'''
            user = User.query.filter_by(
                reg_no=post_data.get('reg_no')
              ).first()
            auth_token = user.encode_auth_token(user.id)
            if auth_token:
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully logged in.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(responseObject)), 200
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500
   
    def test_user_login(self):
        """ User Login Tests """
        res = self.client().post('/login', headers={'Content-Type': 'application/json'}, data=json.dumps(self.user))
        self.assertEqual(res.status_code, 201)
        res = self.client().post('/login', headers={'Content-Type': 'application/json'}, data=json.dumps(self.user))
        json_data = json.loads(res.data)
        self.assertTrue(json_data.get('jwt_token'))
        self.assertEqual(res.status_code, 200)

    def test_admin_login_with_invalid_password(self):
        """ User Login Tests with invalid credentials """
        admin1 = {
          'password': 'admin',
          'email': 'admin@mail.com',
        }
        res = self.client().post('/admin/login', headers={'Content-Type': 'application/json'}, data=json.dumps(admin1))
        json_data = json.loads(res.data)
        self.assertFalse(json_data.get('jwt_token'))
        self.assertEqual(json_data.get('error'), 'invalid credentials')
        self.assertEqual(res.status_code, 400)

    def test_user_login_with_invalid_reg_no(self):
        """ User Login Tests with invalid credentials """
        user = {
          'password': 'password!',
          'reg_no': '13/U/147993/PSA',
        }
        res = self.client().post('/users/login', headers={'Content-Type': 'application/json'}, data=json.dumps(user))
        json_data = json.loads(res.data)
        self.assertFalse(json_data.get('jwt_token'))
        self.assertEqual(json_data.get('error'), 'invalid credentials')
        self.assertEqual(res.status_code, 400)

    def test_user_creation(self):
        """ test user creation with valid credentials """
        res = self.client().post('/users/', headers={'Content-Type': 'application/json'}, data=json.dumps(self.user))
        json_data = json.loads(res.data)
        self.assertTrue(json_data.get('jwt_token'))
        self.assertEqual(res.status_code, 201)

    def test_user_get_me(self):
        """ Test User Get Me """
        res = self.client().post('/users/', headers={'Content-Type': 'application/json'}, data=json.dumps(self.user))
        self.assertEqual(res.status_code, 201)
        api_token = json.loads(res.data).get('jwt_token')
        res = self.client().get('/users/me', headers={'Content-Type': 'application/json', 'api-token': api_token})
        json_data = json.loads(res.data)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json_data.get('reg_no'), '13/U/147993/PSA')   

    def test_delete_user(self):
        """ Test user Delete """
        res = self.client().post('/users/', headers={'Content-Type': 'application/json'}, data=json.dumps(self.user))
        self.assertEqual(res.status_code, 201)
        api_token = json.loads(res.data).get('jwt_token')
        res = self.client().delete('/users/me', headers={'Content-Type': 'application/json', 'api-token': api_token})
        self.assertEqual(res.status_code, 204)   

    def test_registration(self):
        """ Test for user registration """
        with self.client:
            response = self.client.post(
                '/register',
                data=json.dumps(dict(
                    reg_no='13/U/147993/PSA',
                    password='123456'
                )),
                content_type='application/json'
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully registered.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 201)



        
if __name__ == '__main__':
    unittest.main()
