import logging
logging.basicConfig(filename="main.log", filemode='w', level=logging.DEBUG)
import csv, os, yaml
from evive_connectors import cassandra_connector as c



config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "etc")
default_conf = yaml.safe_load(open(os.path.join(config_path, "default.yml")))

# Writing output to csv files 
def writeFile(file, data):
    data.sort()
    logging.debug("Writing output in CSV file")
    if len(data):
        with open(file, 'w') as csvfile: 
            # creating a csv writer object 
            csvwriter = csv.writer(csvfile)
                
            # writing the data rows 
            csvwriter.writerows(data)

            logging.debug("Created file "+file)


def writeMultipleFile(data):
    for key, val in data.items():
        writeFile(key, val)


def writeAWSFile(head, data):

    logging.debug("Writing aws iam users permissions in CSV file")

    with open('aws_iam_users.csv', 'w') as file:
        writer = csv.writer(file)

        #writing heading
        writer.writerows(head)

        #writing rows
        writer.writerows(data)

        logging.debug("aws file created")




# reading and extracting data in lists
def readFile(filename, rows_only = False):

    rows = []
   
    if os.path.isfile(filename):
        # reading csv file
        with open(filename, 'r') as csvfile:

            # creating a csv reader object
            csvreader = csv.reader(csvfile)

            # extracting field names through first row
            fields = next(csvreader)

            # extracting each data row one by one
            for row in csvreader:
                if rows_only:
                    rows.append(row[0])
                else:
                    rows.append(row)
                

            if rows_only:
                return rows
            else:
                return fields, rows
    else:
        logging.error("File not exists on given path "+ filename)


# Return the index for field name
def getIndex(K, fields):
    # return [idx for idx, val in enumerate(fields) if K in val.lower()][0]
    
    for idx, val in enumerate(fields):
        if K.lower() == val.lower():
            return idx
    
    return False

#comparing users with HR Portal Active users
def compareFile(name, app_users, active_users_list, check_if_service = True):
    
    logging.debug("comparing %s with active users", name)

    finalActiveUsers = []
    notInHrList = []
    serviceAccount = []
    
    for user in app_users:
        if user.lower() in active_users_list:
            finalActiveUsers.append([user])
        elif user.lower() in default_conf.get('service_accounts') and check_if_service:
            serviceAccount.append([user])
        else:
            notInHrList.append([user])

    if check_if_service:
        writeFile(name+'_service_account.csv', serviceAccount)
   
    writeFile(name+'_active_users.csv', finalActiveUsers)
    writeFile(name+'_not_in_hr_users.csv', notInHrList)



def get_ibot_users(plugin):
    pass

    # users = []

    # if plugin:
    #     try:
    #         logging.debug("creating cassandra session")
    #         session = c.Cassandra().session
    #         if session:
    #             rows = session.execute("select * from evive_housekeeping.user_journal;")
    #             for row in rows:

    #                 if row.access and plugin in row.access.keys():
    #                     if  row.status == "active":
    #                         users.append(row.username)
    #             return users
    #         else:
    #             logging.error("Failed connecting to Cassandra",)


    #     except Exception as error:
    #         logging.exception("Failed connecting to Cassandra Error: %s", error)
    # else:
    #     logging.debug("No plugin mentioned")


