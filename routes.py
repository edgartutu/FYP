from flask_restful import Api
from project.users.views import Register,Login,Logout,ResetPassword,GetAllProjects,PostProjects,ViewPrjects
from project.guest.views import Login,Logout,AssignedProposal
from project.admin.views import Login,Logout,ApproveProject,PostProject,PendingProposal,ProposalComment


def generate_routes(app):
    api = Api(app)
    
    def users(api):
        
        api.add_resource(Register, '/register')

        api.add_resource(Login, '/login-user')

        api.add_resource(Logout, '/logout')

        api.add_resource(ResetPassword, '/reset-password')

        api.add_resource(GetAllProjects, '/getprojects')

        api.add_resource(PostProjects, '/postprojects')

        api.add_resource(ViewPrjects, '/viewprojects')


    def admin(api):

        api.add_resource(Login, '/login-admin')

        api.add_resource(Logout, '/logout-user')

        api.add_resource(ApproveProject, '/approve')

        api.add_resource(PostProject, '/postproject')

        api.add_resource(PendingProposal, '/pendingproposal')

        api.add_resource(ProposalComment, '/proposalcomment')

    def guest(api):

        api.add_resource(Login, '/login-guest')

        api.add_resource(Logout, '/logout-guest')

        api.add_resource(AssignedProposal, '/viewproposals')

         

        

        

        

        

        
        

    

    

    

    

    

    

    

    

    
    
     

     
