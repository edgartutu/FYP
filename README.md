# FYP
url end points 
api.add_resource(Proposal,'/department/<string:name>/<string:school>/<string:program>')
api.add_resource(Allnames,'/students')

for example:

http://127.0.0.1:5000/department/mutawe/engineering/bsc.tel
 and this returns mutawes data since its already in the database
 
http://127.0.0.1:5000/department/john/cedat/bscELE
as well as john

we can be able to Query all existing data

install all the requirements from the requirements.txt file 

i have commented out some lines in the database and these include the login manager and relationships of the tables

am still not sure of the relationships ,so i put that on hold.

My __init__.py involves my database ,i have used sqlite for now,

