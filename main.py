import logging
logging.basicConfig(filename="main.log", filemode='w', level=logging.DEBUG)
import yaml, argparse, os, json
import common
import boto3
from datadog_api_client.v2 import ApiClient, Configuration
from datadog_api_client.v2.api.users_api import UsersApi
from datadog_api_client.v2.api.roles_api import RolesApi
from evive_connectors import cassandra_connector as c


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
            logging.error(default)
            return



    def default(self, confs):

        """
        Default function if file have only one email column
        """
        app_users = []

        if self.fields:	
		# get index for email field

            logging.debug("finding index for required columns")

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
            logging.debug("finding index for required columns")
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
            logging.debug("finding index for required columns")
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
            logging.debug("finding index for required columns")
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
            logging.debug("finding index for required columns")

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
            logging.debug("finding index for required columns")

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

    
    def ibot(self):
        confs = default_conf.get('tools')['IBOT']

        plugins = []
        
        if default_conf['default_env'] == confs['dev_env']:
            plugins = confs['dev_plugin']
            filename = confs['dev_filename']
        elif default_conf['default_env'] == confs['uat_env']:
            plugins = confs['uat_plugin']
            filename = confs['uat_filename']
        elif default_conf['default_env'] == confs['prod_env']:
            plugins = confs['prod_plugin']
            filename = confs['prod_filename']


        for plugin in plugins:
            users = common.get_ibot_users(plugin)
            users.sort()
            common.compareFile(filename+'_'+plugin, users, self.active_users)
            
        

    def kibana(self, pool_id):

        confs = default_conf.get('tools')['Kibana'] 

        try:
            logging.debug("connecting aws cognito...")
            cognito_client = boto3.client(
                'cognito-idp',
                region_name = 'us-east-1') 

            output = cognito_client.list_users(UserPoolId = pool_id)
            active = []
            inactive = []

            env = default_conf.get('default_env')

            for value in output["Users"]:
                if  env.lower() == confs['dev_env']:
                    username = value['Username'].split('_')[1]
                elif env.lower() == confs['prod_env'] or env.lower() == confs['uat_env']:
                    username = value['Username']+confs['email_val']
                else:
                    logging.error("Environment not recognized ")
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

        

    def aws(self):
        
        confs = default_conf.get('tools')['AWS']
        
        """
        creating Boto3 client using AWS command line credentials
        fetching users, policies, mfa, groups and group policies

        """

        try:
            logging.debug("connecting aws iam...")
           
            iam_client = boto3.client('iam')
                
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


        except Exception as error:
            logging.exception("Failed connecting to AWS Error: %s", error)
            
   
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

    def datadog(self):
        
        """
        Setting environment variables
        then using users api endpoint to fetch user list
        """

        confs = default_conf.get('tools')['Datadog']

        try:

            secret_manager = boto3.client('secretsmanager')

            secrets = secret_manager.get_secret_value(
                SecretId=confs['secret_name'],
                region_name='us-east-1'

            )
            if 'SecretString' in secrets:
            # if True:
                datadog_keys  = json.loads(secrets['SecretString']) 

                #setting enviroment variables
                os.environ['DD_SITE'] = confs['site']
                os.environ['DD_API_KEY'] = datadog_keys['DATADOG_API_KEY']
                os.environ['DD_APP_KEY'] = datadog_keys['DATADOG_APP_KEY'].lower()


                active = []
                admins = []

                logging.debug("calling datadog API...")
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
                        if key.attributes.status == confs['status_val']:
                            admins.append(key.attributes.email)

                    #calling users API
                    api_instance = UsersApi(api_client)
                    response = api_instance.list_users(page_size = confs['page_size'], filter_status = confs['active_filter'])
                
                    for key in response['data']:
                        if key.attributes.email not in admins:
                            active.append(key.attributes.email)
                
                common.compareFile(confs['filename'], active, self.active_users)
                common.compareFile(confs['filename']+"_admin", admins, self.active_users)
            else:
                logging.debug("No secret found")
                    
        except Exception as error:
            logging.exception("Failed creating datadog report Error: %s", error)
                


    # To filter gsuite file
    def gsuite(self):

        confs = default_conf.get('tools')['Gsuite']

        if self.fields:
            logging.debug("finding index for required columns")
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
            logging.debug("finding index for required columns")
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
            
            logging.debug("finding index for required columns")
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
            logging.debug("finding index for required columns")
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


    command_parser = default_conf.get('command_parser')
    
    #creating Parent parser
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='sub-command help')

    logging.debug("Starting to get required arguments")


    #adding parser_a for AWS
    parser_a = subparsers.add_parser(command_parser['aws'], help='To review aws iam users')
    parser_a.set_defaults(which=command_parser['aws'])

    #adding parser_b for Other files
    parser_b = subparsers.add_parser(command_parser['other'], help='To review other tools')
    parser_b.set_defaults(which=command_parser['other'])

    parser_b.add_argument('--app_name', help='''app name
                            ex: slack''', dest = "application_name", required=True)
    parser_b.add_argument('--app_file', help='''app users CSV file path
                            ex: /users/home/abc/slack.csv''', dest = "application_file", required=True)
    parser_b.add_argument('--users_file', help='''active users CSV file path
                            ex: /users/home/abc/active_users.csv''', dest = "active_users_file", required=True)

    #adding parser_c for Datadog
    parser_c = subparsers.add_parser(command_parser['datadog'], help='To review datadog users')
    parser_c.set_defaults(which=command_parser['datadog'])

    parser_c.add_argument('--users_file', help='''active users CSV file path
                            ex: /users/home/abc/active_users.csv''', dest = "active_users_file", required=True)


    #adding parser_d for AWS Kibana
    parser_d = subparsers.add_parser(command_parser['kibana'], help='To review kibana users')
    parser_d.set_defaults(which=command_parser['kibana'])
    
    parser_d.add_argument('--pool_id', help='''Pool ID''', dest = "pool_id", required=True)
    parser_d.add_argument('--users_file', help='''active users CSV file path
                            ex: /users/home/abc/active_users.csv''', dest = "active_users_file", required=True)

    
    parser_e = subparsers.add_parser(command_parser['ibot'], help='To review IBOT access')
    parser_e.set_defaults(which=command_parser['ibot'])

    parser_e.add_argument('--users_file', help='''active users CSV file path
                            ex: /users/home/abc/active_users.csv''', dest = "active_users_file", required=True)
    

    args = vars(parser.parse_args())

    if args.get('which') ==  command_parser['aws']:

        #creating class object and  calling AWS function

        logging.debug("Calling AWS function ...")
        object = Filter(active_users_file = args.get('active_users_file'))
        object.aws()

    elif args.get('which') ==  command_parser['other']:
        
        #creating class object and  calling redirect function

        if os.path.isfile(args.get('application_file')):
            if os.path.isfile(args.get('active_users_file')):
                logging.debug("calling %s function", args.get('application_name'))
                object = Filter(app_name = args.get('application_name'), app_file = args.get('application_file'), active_users_file = args.get('active_users_file'))
                object.redirect()
            else:
                logging.error("%s file not exists ", args.get('active_users_file'))    
        else:
            logging.error("%s file not exists ", args.get('application_name')) 
    
    elif args.get('which') ==  command_parser['datadog']:

        #creating class object and  calling Datadog function
        
        logging.debug("Calling datadog function ...")
        object = Filter(active_users_file = args.get('active_users_file'))
        object.datadog()


    elif args.get('which') ==  command_parser['kibana']:

        #creating class object and  calling AWS function
        logging.debug("Calling kibana function ...")
        object = Filter(active_users_file = args.get('active_users_file'))
        object.kibana(args.get('pool_id'), args.get('env'))
    
    
    elif args.get('which') ==  command_parser['aws']:

        #creating class object and  calling IBOT function
        logging.debug("Calling ibot function ...")
        object = Filter(active_users_file = args.get('active_users_file'))
        object.ibot()
    else:
        logging.debug("Wrong command line arguments")


