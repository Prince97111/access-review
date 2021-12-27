import yaml, argparse, os, logging
import common
import boto3
from datadog_api_client.v2 import ApiClient, Configuration
from datadog_api_client.v2.api.users_api import UsersApi
from datadog_api_client.v2.api.roles_api import RolesApi

logging.basicConfig(filename="main.log")

config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "etc")
default_conf = yaml.safe_load(open(os.path.join(config_path, "default.yml")))

class Filter():

    def __init__(self, app_name="", app_file="", active_users_file=""):

        """
        Reading CSV files and initializing users lists
        """

        if active_users_file:
            self.active_users = common.readFile(active_users_file, True)

        if app_name and app_file:
            self.fields, self.rows = common.readFile(app_file)
            self.app_name = app_name

    
    def redirect(self):

        default = "Incorrect app name"     
        
        """
        Calling function as per given app name by user
        gettting function name from yaml conf
        """

        if self.app_name in default_conf.get('function_redirection') :
            return getattr(self, default_conf.get('function_redirection')[self.app_name], lambda: default)()
        else:
            print(default)
            logging.error(default)
            return



    def default(self, confs):

        """
        Default function if file have only one email column
        """
        app_users = []

        if self.fields:	
		# get index for email field
            email_index = common.getIndex(confs['email_col'], self.fields)
            
            for row in self.rows:
                if row:
                    if(default_conf['default_email'] in row[email_index]):
                        app_users.append(row[email_index])

            common.compareFile(confs['filename'], app_users, self.active_users)
            
        else:
            logging.error("File format is not valid")


    def jetbrains(self):

        """
        Calling default function as we have only one column Email 
        """

        confs = default_conf.get('tools')['Jetbrains']
        self.default(confs)


    def aviatrix(self):

        """
        Calling default function as we have only one column Email 
        """

        confs = default_conf.get('tools')['Aviatrix']
        self.default(confs)


    def crowdstrike(self):
        confs = default_conf.get('tools')['Crowdstrike']
        if self.fields:
            # get index for email field
            email_index = common.getIndex(confs['email_col'], self.fields)

            #get index for role field
            role_index = common.getIndex(confs['role_col'], self.fields)

            active = []
            inactive = []
            admins = []

            if email_index is not False and role_index is not False:
                for row in self.rows:
                    if row:
                        if [ele for ele in confs['role_val'] if(ele in row[role_index].lower())]:
                            admins.append(row[email_index])
                        else:
                            active.append(row[email_index])
                        

                common.writeFile(confs['filename']+'_inactive.csv', inactive)
                common.compareFile(confs['filename'], active, self.active_users)
                common.compareFile(confs['filename']+'_admin', admins, self.active_users, False)

            else:
                logging.error("File format is not valid")
        else:
            logging.error("File format is not valid")


    def digicert(self):
        confs = default_conf.get('tools')['Digicert']
        if self.fields:
            # get index for email field
            email_index = common.getIndex(confs['email_col'], self.fields)

            # get index for status field
            status_index = common.getIndex(confs['status_col'], self.fields)

            #get index for role field
            role_index = common.getIndex(confs['role_col'], self.fields)

            active = []
            inactive = []
            admins = []

            if email_index is not False and status_index is not False:
                for row in self.rows:
                    if row:
                        if row[status_index].lower() in confs['status_val']:
                            if row[role_index].lower() in confs['role_val']:
                                admins.append(row[email_index])
                            else:
                                active.append(row[email_index])
                        else:
                            inactive.append([row[email_index]])
                        

                common.writeFile(confs['filename']+'_inactive.csv', inactive)
                common.compareFile(confs['filename'], active, self.active_users)
                common.compareFile(confs['filename']+'_admin', admins, self.active_users, False)

            else:
                logging.error("File format is not valid")
        else:
            logging.error("File format is not valid")


    
    def zscaler(self):
        confs = default_conf.get('tools')['Zscaler']
        if self.fields:
            # get index for email field
            email_index = common.getIndex(confs['email_col'], self.fields)

            # get index for status field
            status_index = common.getIndex(confs['status_col'], self.fields)

            #get index for role field
            role_index = common.getIndex(confs['role_col'], self.fields)

            active = []
            inactive = []
            admins = []

            if email_index is not False and status_index is not False:
                for row in self.rows:
                    if row:
                        if row[status_index].lower() in confs['status_val']:
                            if row[role_index].lower() in confs['role_val']:
                                admins.append(row[email_index])
                            else:
                                active.append(row[email_index])
                        else:
                            inactive.append([row[email_index]])
                        

                common.writeFile(confs['filename']+'_inactive.csv', inactive)
                common.compareFile(confs['filename'], active, self.active_users)
                common.compareFile(confs['filename']+'_admin', admins, self.active_users, False)

            else:
                logging.error("File format is not valid")
        else:
            logging.error("File format is not valid")


    def duo(self):
        confs = default_conf.get('tools')['Duo']

        if self.fields:

            # get index for email field
            email_index = common.getIndex(confs['email_col'], self.fields)


            # get index for status field
            status_index = common.getIndex(confs['status_col'], self.fields)

            active = []
            inactive = []
            if email_index is not False and status_index is not False:
                for row in self.rows:
                    if row:
                        if(row[status_index].lower() in confs['status_val'] ):
                            active.append(row[email_index]+confs["email_val"])
                        else:
                            inactive.append([row[email_index]+confs["email_val"]])
                    

                common.writeFile(confs['filename']+'_inactive.csv', inactive)
                common.compareFile(confs['filename'], active, self.active_users)
            else:
                logging.debug("File format is not valid")
        else:
            logging.debug("File format is not valid")

    
    def meraki(self):
        confs = default_conf.get('tools')['Meraki']

        if self.fields:

            # get index for email field
            email_index = common.getIndex(confs['email_col'], self.fields)

            #get index for role field
            role_index = common.getIndex(confs['role_col'], self.fields)

            active = []
            admins = []
            if email_index is not False and role_index is not False:
                for row in self.rows:
                    if row:
                        if(row[role_index].lower() in confs['role_val'] ):
                            admins.append(row[email_index])
                        else:
                            active.append(row[email_index])
                    

                common.compareFile(confs['filename']+'_admin', admins, self.active_users)
                common.compareFile(confs['filename'], active, self.active_users)
            else:
                logging.error("File format is not valid")
        else:
            logging.error("File format is not valid")

    
    def kibana(self, access_key, secret_key, session_token, pool_id, env):

        confs = default_conf.get('tools')['Kibana'] 

        try:
            cognito_client = boto3.client(
                'cognito-idp',
                region_name = 'us-east-1',
                aws_access_key_id = access_key, 
                aws_secret_access_key = secret_key, 
                aws_session_token = session_token) 

            output = cognito_client.list_users(UserPoolId = pool_id)
            active = []
            inactive = []

            for value in output["Users"]:
                if env.lower() == 'dev':
                    username = value['Username'].split('_')[1]
                elif env.lower() == 'prod' or env.lower() == 'uat':
                    username = value['Username']+confs['email_val']
                else:
                    logging.error("Environment not recognized ")
                    print("Environment not recognized ")
                    break
                    
                if value['Enabled']:
                    active.append(username)
                else:
                    inactive.append([username])
            
            if active:
                common.compareFile(confs['filename'], active, self.active_users)
            
            common.writeFile(confs['filename']+'_inactive.csv', inactive)

        except Exception as error:
            logging.exception("Failed connecting to AWS Error: %s", error)

        

    def aws(self, access_key, secret_key, session_token):
        
        confs = default_conf.get('tools')['AWS']
        # session = boto3.Session(profile_name="dev-iam")
        # iam = session.client("iam")


        """
        creating Boto3 client using AWS command line credentials
        fetching users, policies, mfa, groups and group policies

        """

        try:
            iam_client = boto3.client(
                'iam',
                aws_access_key_id = access_key, 
                aws_secret_access_key = secret_key, 
                aws_session_token = session_token) 
        except Exception as error:
            logging.exception("Failed connecting to AWS Error: %s", error)
            
        users = iam_client.list_users()
        final_output  = []
        for key in users['Users']:
            
            username = key['UserName']

            #get user policies
            policies =  self.get_user_policies(username, iam_client)

            #get user groups
            groups_list =  iam_client.list_groups_for_user(UserName=username)
            user_groups = []
            for group in groups_list['Groups']:
                user_groups.append(group['GroupName'])
            
            if len(user_groups):
                groups = ",".join(user_groups)
                groups_policies = self.get_group_policies(groups, iam_client)
            else:
                groups = "-"
                groups_policies = "-"

            #mfa_status
            mfa_devices = iam_client.list_mfa_devices(UserName=username)

            if not len(mfa_devices['MFADevices']):
                mfa = False   
            else:
                mfa = True
            
            final_output.append([username, policies, groups, groups_policies, mfa])

        
        file_header = [confs['header']] 
        common.writeAWSFile(file_header, final_output)
        

            


    def get_user_policies(self, username, iam_client):

        """
        Fetching policies for username
        """

        policy_names = []
        # This is for AWS managed policies 
        attached_user_policies = (iam_client.list_attached_user_policies(UserName=username)['AttachedPolicies'])

        for policy in attached_user_policies:
            policy_names.append(policy['PolicyName'])
        # This is for inline policies
        user_policies = (iam_client.list_user_policies(UserName=username)['PolicyNames'])
        
        for policy in user_policies:
            policy_names.append(policy)
    

        if len(policy_names):
            return ",".join(policy_names)
        else:
            return '-'

    def get_group_policies(self, user_groups, iam_client):

        """
        Fetching policies for groupname
        """

        groups = user_groups.split(",")
        
        policy_names = []
        for group in groups:
            # This is for AWS managed policies
            attached_group_policies = (iam_client.list_attached_group_policies(GroupName=group)['AttachedPolicies'])
            for policy in attached_group_policies:
                policy_names.append(policy['PolicyName'])
                
            # This is for inline policies 
            group_policies = (iam_client.list_group_policies(GroupName=group)['PolicyNames'])
            for policy in group_policies:
                policy_names.append(policy)
        
        return ",".join(policy_names)

    def datadog(self, app_key, api_key):
        
        """
        Setting environment variables
        then using users api endpoint to fetch user list
        """

        confs = default_conf.get('tools')['Datadog']

        try:
            
            #setting enviroment variables
            os.environ['DD_SITE'] = confs['site']
            os.environ['DD_API_KEY'] = api_key
            os.environ['DD_APP_KEY'] = app_key


            active = []
            admins = []

            
            configuration = Configuration()
            with ApiClient(configuration) as api_client:

                #calling roles API
                role_api_instance = RolesApi(api_client)
                role_res = role_api_instance.list_roles()

                for key in role_res['data']:
                    if key.attributes.name.lower() in confs['role_val']:
                        admin_role_id = key.id
                        break
                
                #getting users for admin role
                admin_res = role_api_instance.list_role_users(role_id=admin_role_id)

                for key in admin_res['data']:
                    admins.append(key.attributes.email)

                #calling users API
                api_instance = UsersApi(api_client)
                response = api_instance.list_users(page_size = confs['page_size'], filter_status = confs['active_filter'])
            
                for key in response['data']:
                    if key.attributes.email not in admins:
                        active.append(key.attributes.email)
            
            common.compareFile(confs['filename'], active, self.active_users)
            common.compareFile(confs['filename']+"_admin", admins, self.active_users)
                    
        except Exception as error:
            logging.exception("Failed creating datadog report Error: %s", error)
                


    # To filter gsuite file
    def gsuite(self):

        confs = default_conf.get('tools')['Gsuite']

        if self.fields:

            # get index for email field
            email_index = common.getIndex(confs['email_col'], self.fields)


            # get index for status field
            status_index = common.getIndex(confs['status_col'], self.fields)

            active = []
            inactive = []
            if email_index is not False and status_index is not False:
                for row in self.rows:
                    if row:
                        if(row[status_index].lower() in confs['status_val'] ):
                            active.append(row[email_index])
                        else:
                            inactive.append([row[email_index]])
                    

                common.writeFile(confs['filename']+'_inactive.csv', inactive)
                common.compareFile(confs['filename'], active, self.active_users)
            else:
                logging.error("File format is not valid")
        else:
            logging.error("File format is not valid")



    # To filter lucidcharts file
    def lucidchart(self):
        confs = default_conf.get('tools')['Lucid']
        if self.fields:
            # get index for email field
            email_index = common.getIndex(confs['email_col'], self.fields)

            # get index for status field
            status_index = common.getIndex(confs['status_col'], self.fields)

            #get index for role field
            role_index = common.getIndex(confs['role_col'], self.fields)

            licensed = []
            non_licensed = []
            admins = []

            if email_index is not False and status_index is not False:
                for row in self.rows:
                    if row:
                        if row[status_index].lower() in confs['status_val']:
                            
                            if row[role_index].lower() in confs['role_val']:
                                admins.append(row[email_index])
                            else:
                                licensed.append(row[email_index])
                        else:
                            non_licensed.append(row[email_index])
            else:
                logging.error("File format is not valid")

            common.compareFile(confs['filename']+'_licensed', licensed, self.active_users)
            common.compareFile(confs['filename']+'_non_licensed', non_licensed, self.active_users)
            common.compareFile(confs['filename']+'_admin', admins, self.active_users, False)
        else:
            logging.error("File format is not valid")

    def virtru(self):
        confs = default_conf.get('tools')['Virtru']
        if self.fields:
            

            # get index for email field
            email_index = common.getIndex(confs['email_col'], self.fields)
            
            # get index for status field
            status_index = common.getIndex(confs['status_col'], self.fields)

            # get index for role field
            role_index = common.getIndex(confs['role_col'], self.fields)
            
            app_users = []
            in_active = []
            admins = []
            others = []
            
            if email_index is not False and status_index is not False:
                for row in self.rows:			
                    if default_conf['default_email'] in row[email_index]:
                        if row[status_index].lower() in confs['status_val']:
                            if row[role_index].lower() in confs['role_val']:
                                admins.append(row[email_index])
                            else:                                
                                app_users.append(row[email_index])
                        else:
                            in_active.append([row[email_index]])
                    else:
                        others.append([row[email_index]])

                output_data = {
                    confs['filename']+'_inactive_users.csv' : in_active,
                    confs['filename']+'_extras_rows.csv' : others
                    
                }

                common.writeMultipleFile(output_data)

                common.compareFile(confs['filename'], app_users, self.active_users)
                common.compareFile(confs['filename']+'_admin', admins, self.active_users, False)
            else:
                logging.error("File format is not valid")
        else:
            logging.error("File format is not valid")

        return

    def slack(self):
        confs = default_conf.get('tools')['Slack']
        if self.fields:
            # get index for email field
            email_index = common.getIndex(confs['email_col'], self.fields)

            # get index for status field
            status_index = common.getIndex(confs['status_col'], self.fields)

            active = []
            inactive = []
            admins = []
            bot = []
            other = []

            for row in self.rows:
                if row:
                    if row[status_index].lower() in confs['status_val']:
                        active.append(row[email_index])
                    elif row[status_index].lower() in confs['admin_val']:
                        admins.append(row[email_index])
                    elif row[status_index].lower() in confs['bot_val']:
                        bot.append([row[email_index]])
                    elif row[status_index].lower() in confs['deactivated']:
                        inactive.append(row[email_index])
                    else:
                        other.append([row[email_index]])


            common.writeFile(confs['filename']+'_bot.csv', bot)    
            common.writeFile(confs['filename']+'_other.csv', other)
           
            common.compareFile(confs['filename'], active, self.active_users)
            common.compareFile(confs['filename']+'_admin', admins, self.active_users, False)
        else:
            logging.error("File format is not valid")



if __name__ == "__main__":
    
    #creating Parent parser
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='sub-command help')


    #adding parser_a for AWS
    parser_a = subparsers.add_parser('aws', help='To review aws iam users')
    
    parser_a.add_argument('--access_key', help='AWS Access Key ID', dest = "access_key", required=True)
    parser_a.add_argument('--secret_key', help='AWS Secret Access Key', dest = "secret_key", required=True)
    parser_a.add_argument('--session_token', help='AWS Session Token', dest = "session_token", required=True)
    parser_a.add_argument('--users_file', help='''active users CSV file path
                            ex: /users/home/abc/active_users.csv''', dest = "active_users_file", required=True)
    

    #adding parser_b for Other files
    parser_b = subparsers.add_parser('other', help='To review other tools')
    parser_b.add_argument('--app_name', help='''app name
                            ex: slack''', dest = "application_name", required=True)
    parser_b.add_argument('--app_file', help='''app users CSV file path
                            ex: /users/home/abc/slack.csv''', dest = "application_file", required=True)
    parser_b.add_argument('--users_file', help='''active users CSV file path
                            ex: /users/home/abc/active_users.csv''', dest = "active_users_file", required=True)

    #adding parser_c for Datadog
    parser_c = subparsers.add_parser('datadog', help='To review datadog users')
    parser_c.add_argument('--app_key', help='Application key', dest = "app_key", required=True)
    parser_c.add_argument('--api_key', help='Api key', dest = "api_key", required=True)
    parser_c.add_argument('--users_file', help='''active users CSV file path
                            ex: /users/home/abc/active_users.csv''', dest = "active_users_file", required=True)


    #adding parser_d for AWS
    parser_d = subparsers.add_parser('kibana', help='To review kibana users')
    
    parser_d.add_argument('--access_key', help='AWS Access Key ID', dest = "access_key", required=True)
    parser_d.add_argument('--secret_key', help='AWS Secret Access Key', dest = "secret_key", required=True)
    parser_d.add_argument('--session_token', help='AWS Session Token', dest = "session_token", required=True)
    parser_d.add_argument('--pool_id', help='''Pool ID''', dest = "pool_id", required=True)
    parser_d.add_argument('--env', help='''Environment''', dest = "env", required=True)
    parser_d.add_argument('--users_file', help='''active users CSV file path
                            ex: /users/home/abc/active_users.csv''', dest = "active_users_file", required=True)
    

    args = vars(parser.parse_args())

    if args.get('env') and args.get('pool_id') and args.get('access_key') and args.get('active_users_file') and args.get('secret_key') and args.get('session_token'):

        #creating class object and  calling AWS function

        object = Filter(active_users_file = args.get('active_users_file'))
        object.kibana(args.get('access_key'), args.get('secret_key'), args.get('session_token'), args.get('pool_id'), args.get('env'))
    
    elif args.get('access_key') and args.get('active_users_file') and args.get('secret_key') and args.get('session_token'):

        #creating class object and  calling AWS function

        object = Filter(active_users_file = args.get('active_users_file'))
        object.aws(args.get('access_key'), args.get('secret_key'), args.get('session_token'))

    elif args.get('app_key') and args.get('api_key') and args.get('active_users_file'):

        #creating class object and  calling Datadog function

        object = Filter(active_users_file = args.get('active_users_file'))
        object.datadog(args.get('app_key'), args.get('api_key'))

    elif args.get('application_name') and args.get('application_file') and args.get('active_users_file'):
        
        #creating class object and  calling redirect function

        if os.path.isfile(args.get('application_file')):
            if os.path.isfile(args.get('active_users_file')):
                object = Filter(app_name = args.get('application_name'), app_file = args.get('application_file'), active_users_file = args.get('active_users_file'))
                object.redirect()
            else:
                logging.error("%s file not exists ", args.get('active_users_file'))    
        else:
            logging.error("%s file not exists ", args.get('application_name'))
    else:
        print("Wrong command line arguments")


