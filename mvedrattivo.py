#!/usr/bin/env python3
import pycurl, base64, json, requests, urllib.parse, time,sys, argparse, subprocess, logging,re
from io import BytesIO
from argparse import ArgumentParser, RawTextHelpFormatter
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings("ignore")

botsink_ip='10.1.0.4'
botsink_port='8443'
user_name='api'
user_pass=''
edr_data_grab_time=2
attivo_data_grab_time=7
edr_hook='https://api.soc.ap-southeast-2.mcafee.com/wh/v1/webhook/915641aa-919e-11eb-9b07-8c35ce6c722a'
edr_user=''
edr_pass=''
edr_region='SY'
edr_limit = '50'
edr_data_type= ''


class EDRRTS():
    def __init__(self):
        if edr_region == 'EU':
            self.base_url = 'https://api.soc.eu-central-1.mcafee.com'
        elif edr_region == 'US':
            self.base_url = 'https://api.soc.mcafee.com'
        elif edr_region == 'SY':
            self.base_url = 'https://api.soc.ap-southeast-2.mcafee.com'
        self.verify = True
        self.request = requests.Session()
        self.query = None
        user = edr_user
        pw = edr_pass
        creds = (user, pw)
        self.auth(creds)
       
    def auth(self, creds):
        r = requests.get(self.base_url + '/identity/v1/login', auth=creds)
        res = r.json()

        if r.status_code == 200:
            token = res['AuthorizationToken']
            self.headers = {'Authorization': 'Bearer {}'.format(token)}
            print('AUTHENTICATION: Successfully authenticated.')
        else:
            print('ERROR: Something went wrong during the authentication')
            sys.exit()

    def searchhash(self,filehash):
        queryId = None
        self.query = filehash
        if len(str(self.query)) == 32:
            type = 'md5'
        elif len(str(self.query)) == 40:
            type = 'sha1'
        elif len(str(self.query)) == 64:
            type = 'sha256'
        else:
            print('ERROR: Something went wrong with the Hash input')
            sys.exit()

        payload = {
            "projections": [
                {
                    "name": "HostInfo",
                    "outputs": ["hostname", "ip_address"]
                }, {
                    "name": "Files",
                    "outputs": ["name", str(type), "status", "full_name"]
                }
            ],
            "condition": {
                "or": [{
                    "and": [{
                        "name": "Files",
                        "output": str(type),
                        "op": "EQUALS",
                        "value": str(self.query)
                    }]
                }]
            }
        }

        res = self.request.post(self.base_url + '/active-response/api/v1/searches',
                                headers=self.headers,
                                json=payload)
        try:
            if res.status_code == 200:
                queryId = res.json()['id']
                print('SEARCH: MVISION EDR search got started successfully')
            else:
                print('ERROR: Could not find the query ID.')
        except Exception as e:
            print('ERROR: Could not find the query ID. Error: {}'.format(e))
            sys.exit()

        return queryId

    def search_network(self,pid):
        queryId = None
        payload = {
            "projections": [
                {
                    "name": "HostInfo",
                    "outputs": ["hostname", "ip_address"]
                }, {
                    "name": "NetworkFlow",
                    "outputs": ["src_ip", "dst_ip", "status", "process_id"]
                }
            ],
            "condition": {
                "or": [{
                    "and": [{
                        "name": "NetworkFlow",
                        "output": "process_id",
                        "op": "EQUALS",
                        "value": str(pid)
                    }]
                }]
            }
        }

        res = self.request.post(self.base_url + '/active-response/api/v1/searches',
                                headers=self.headers,
                                json=payload)
        try:
            if res.status_code == 200:
                queryId = res.json()['id']
                print('SEARCH: MVISION EDR search got started successfully')
            else:
                print('ERROR: Could not find the query ID.')
        except Exception as e:
            print('ERROR: Could not find the query ID. Error: {}'.format(e))
            sys.exit()

        return queryId

    def search_pid(self,pid):
        queryId = None
        payload = {
            "projections": [
                {
                    "name": "HostInfo",
                    "outputs": ["hostname", "ip_address"]
                }, {
                    "name": "Processes",
                    "outputs": ["id"]
                }
            ],
            "condition": {
                "or": [{
                    "and": [{
                        "name": "Processes",
                        "output": "id",
                        "op": "EQUALS",
                        "value": str(pid)
                    }]
                }]
            }
        }

        res = self.request.post(self.base_url + '/active-response/api/v1/searches',
                                headers=self.headers,
                                json=payload)
        try:
            if res.status_code == 200:
                queryId = res.json()['id']
                print('SEARCH: MVISION EDR search got started successfully')
            else:
                print('ERROR: Could not find the query ID.')
        except Exception as e:
            print('ERROR: Could not find the query ID. Error: {}'.format(e))
            sys.exit()

        return queryId    

    def search_status(self, queryId):
        status = False
        res = self.request.get(self.base_url + '/active-response/api/v1/searches/{}/status'.format(str(queryId)), headers=self.headers)
        if res.status_code == 200:
            if res.json()['status'] == 'FINISHED':
                status = True
            else:
                print('STATUS: Search still in process. Status: {}'.format(res.json()['status']))
        return status

    def search_result(self, queryId):
        res = self.request.get(self.base_url + '/active-response/api/v1/searches/{}/results'.format(str(queryId)), headers=self.headers)
        if res.status_code == 200:
            try:
                items = res.json()['totalItems']
                react_summary = []
                react_summary_r = []
                for item in res.json()['items']:
                    
                    if item['output']['Files|status'] != 'deleted':
                        react_dict = {}
                        react_dict[item['id']] = (item['output']['HostInfo|hostname'],item['output']['Files|full_name'])
                        react_summary.append(react_dict)
                        react_dict_r = {}
                        react_dict_r[item['id']] = item['output']['Files|full_name']
                        react_summary_r.append(react_dict_r)

                print('RESULT: MVISION EDR found {} System/s with this hash. {} of them with the file status CURRENT.'.format(items, len(react_summary)))

                return react_summary,react_summary_r

            except Exception as e:
                print('ERROR: Something went wrong to retrieve the results. Error: {}'.format(e))
                sys.exit()
        else:
            print('ERROR: Something went wrong to retrieve the results.')
            sys.exit()

    def search_result_network(self, queryId):
        res = self.request.get(self.base_url + '/active-response/api/v1/searches/{}/results'.format(str(queryId)), headers=self.headers)
        if res.status_code == 200:
            try:
                items = res.json()['totalItems']
                react_summary = []
                react_summary_r = []
                #print (res.json())
                for item in res.json()['items']:
                    react_dict = {}
                    react_dict = ('hostname '+item['output']['HostInfo|hostname'],'dst '+item['output']['NetworkFlow|dst_ip'],"src "+item['output']['NetworkFlow|src_ip'])
                    react_summary.append(react_dict)
                    react_dict_r = {}
                    react_dict_r[item['id']] = item['output']['NetworkFlow|process_id']
                    react_summary_r.append(react_dict_r)
    
                print('Network RESULT: MVISION EDR found {} System/s with this process comms '.format(items, len(react_summary)))

                return react_summary,react_summary_r

            except Exception as e:
                print('ERROR: Something went wrong to retrieve the results. Error: {}'.format(e))
                sys.exit()
        else:
            print('ERROR: Something went wrong to retrieve the results.')
            sys.exit()        
    
    def search_result_pid(self, queryId):
        res = self.request.get(self.base_url + '/active-response/api/v1/searches/{}/results'.format(str(queryId)), headers=self.headers)
        if res.status_code == 200:
            try:
                items = res.json()['totalItems']
                react_summary = []
                react_summary_r = []
                for item in res.json()['items']:
                    react_dict = {}
                    react_dict = ('hostname '+item['output']['HostInfo|hostname'],'ip '+item['output']['HostInfo|ip_address'])
                    react_summary.append(react_dict)
                    react_dict_r = {}
                    react_dict_r[item['id']] = item['output']['Processes|id']
                    react_summary_r.append(react_dict_r)
    
                print('Search RESULT: MVISION EDR found {} System/s with this process id '.format(items, len(react_summary)))

                return react_summary,react_summary_r

            except Exception as e:
                print('ERROR: Something went wrong to retrieve the results. Error: {}'.format(e))
                sys.exit()
        else:
            print('ERROR: Something went wrong to retrieve the results.')
            sys.exit()        

    
    
    
    def reaction_removefile_execution(self, queryId, systemId, filePath):
        reactionId = None

        payload = {
            "action":"removeFile",
            "searchResultsArguments": {
                "searchId": int(queryId),
                "rowsIds": [str(systemId)],
                "arguments": {}
            },
            "provider": "AR",
            "actionInputs": [
                {
                    "name": "full_name",
                    "value": str(filePath)
                }
            ]
        }

        res = self.request.post(self.base_url + '/remediation/api/v1/actions/search-results-actions',
                              headers=self.headers,
                              json=payload)

        if res.status_code == 201:
            try:
                reactionId = res.json()['id']
                print('REACTION: MVISION EDR reaction got executed successfully')
            except Exception as e:
                print('ERROR: Something went wrong to create reaction. Error: {}'.format(e))
                sys.exit()

        return reactionId

    def reaction_kill_execution(self, queryId, systemId, pid):
        reactionId = None
        
        payload = {
            "action":"killProcess",
            "searchResultsArguments": {
                "searchId": int(queryId),
                "rowsIds": [str(systemId)],
                "arguments": {}
            },
            "provider": "AR",
            "actionInputs": [
                {
                    "name": "pid",
                    "value": str(pid)
                }
            ]
        }
        res = self.request.post(self.base_url + '/remediation/api/v1/actions/search-results-actions',
                                headers=self.headers,
                                json=payload)
        
        if res.status_code == 201:
            try:
                reactionId = res.json()['id']
                print('MVISION EDR reaction got executed successfully')
            except Exception as e:
                print('Something went wrong to create reaction. Error: {}'.format(e))
                sys.exit()

        return reactionId


    def reaction_status(self, reactionId):
        done = False
        res = self.request.get(self.base_url + '/remediation/api/v1/actions/{}/status'.format(str(reactionId)),
                               headers=self.headers)

        if res.status_code == 200:
            try:
                print('STATUS: MVISION EDR Reaction status is {}.'.format(res.json()['status']))
                if res.json()['status'] == 'COMPLETED':
                    done = True
            except Exception as e:
                print('ERROR: Could not get the search ID. Error: {}'.format(e))
                sys.exit()

        return done




class EDRHistory():
    def __init__(self,hostName):
        if edr_region == 'EU':
            self.base_url = 'https://api.soc.eu-central-1.mcafee.com'
        elif edr_region == 'US':
            self.base_url = 'https://api.soc.mcafee.com'
        elif edr_region == 'SY':
            self.base_url = 'https://api.soc.ap-southeast-2.mcafee.com'

        self.verify = True
        self.logger = logging.getLogger('logs')
        self.logger.setLevel('DEBUG')
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.request = requests.Session()

        

        user = edr_user
        pw = edr_pass
        creds = (user, pw)
        self.auth(creds)

        self.hostname = hostName
        self.days = edr_data_grab_time
        self.limit = edr_limit
        self.type = edr_data_type
        self.search = None
        self.pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        

       
    def auth(self, creds):
        r = requests.get(self.base_url + '/identity/v1/login', auth=creds)
        res = r.json()

        if r.status_code == 200:
            token = res['AuthorizationToken']
            self.headers = {'Authorization': 'Bearer {}'.format(token)}
            self.logger.debug('AUTHENTICATION: Successfully authenticated.')
        else:
            self.logger.error('Something went wrong during the authentication')
            sys.exit()

    def get_host(self):
        try:
            query = {"hostname": self.hostname}
            res = self.request.get(self.base_url + '/ft/api/v2/ft/hosts/?filter={}&fields=hostname,maGuid'
                                   .format(json.dumps(query)),
                                   headers=self.headers)

            if res.json()['total'] == 1:
                for host in res.json()['hosts']:
                    maGuid = host['maGuid']
                    return maGuid
            elif res.json()['total'] > 1:
                self.logger.error('Too many hosts found with this Hostname. Please be more specfic.')
                self.logger.error(res.json())
                sys.exit()
            else:
                self.logger.error('Could not find a Host with this Hostname.')
                sys.exit()

        except Exception as error:
            self.logger.error('Error in edr.get_hosts. Error: {}'.format(str(error)))

    def hist_search(self):
        try:
            t_now = datetime.utcnow().strftime(self.pattern)
            t_before = (datetime.utcnow() - timedelta(days=self.days)).strftime(self.pattern)

            query = {
              "$filter": {
                "$and": [
                  {
                    "detectionDate": {
                      "$gte": t_before
                    }
                  },
                  {
                    "detectionDate": {
                      "$lt": t_now
                    }
                  }
                ],
                "maGuid": self.get_host()
              },
              "$sort": {
                "time": -1
              }
            }

            if self.type is not None:
                query['$filter']['tags'] = '@AC.' + self.type

            if self.search is not None:
                query['$filter']['$and'][0]['$term'] = self.search

            res = self.request.get(self.base_url + '/ltc/api/v1/ltc/query/traces/?query={}&limit={}&skip=0'
                                   .format(json.dumps(query), self.limit),
                                   headers=self.headers)

            if res.status_code != 200:
                self.logger.error('edr.hist_search - {0} - {1}'.format(str(res.status_code), res.text))
            else:
                
                edr_result = res.json()
                return edr_result 
                
        except Exception as error:
            self.logger.error('Error in edr.hist_search. Error: {}'.format(str(error)))

    def detect_search(self):
        try:
            t_now = datetime.utcnow().strftime(self.pattern)
            t_before = (datetime.utcnow() - timedelta(days=self.days)).strftime(self.pattern)

            epoch_now = int(time.mktime(time.strptime(t_now, self.pattern)))
            epoch_before = int(time.mktime(time.strptime(t_before, self.pattern)))

            filter = {
                "maGuid": self.get_host()
            }

            severities = ["s1", "s2", "s3", "s4", "s5"]
            if self.type == 'DetectionsAlerts':
                severities.append('s0')

            filter['severities'] = severities

            res = self.request.get(self.base_url + '/mvm/api/v1/middleware/detections?sort=-eventDate&filter={0}&from={1}&to={2}&skip=0&limit={3}&externalOffset=0'
                                   .format(json.dumps(filter), str(epoch_before*1000), str(epoch_now*1000), self.limit),
                                   headers=self.headers)

            if res.status_code != 200:
                self.logger.error('Error in edr.detect_search - {0} - {1}'.format(str(res.status_code), res.text))
            else:
                #self.logger.info(res.json())
                #self.logger.info('Found {0} items.'.format(res.json()['count']))
                edr_result = res.json()
                return edr_result
        except Exception as error:
            self.logger.error('Error in edr.detect_search. Error: {}'.format(str(error)))


def edr_kill_process(opt_pid):
    edrrts=EDRRTS()
    queryId = edrrts.search_pid(opt_pid)
    if queryId is None:
        sys.exit()
    while edrrts.search_status(queryId) is False:
        time.sleep(10)
        results = edrrts.search_result_pid(queryId)
        
        result_json=json.dumps(results[0])
        result_json=json.loads(result_json)
        print(json.dumps(result_json, indent=4, sort_keys=True))
        
        if(results[1]):
            print ("Do you want to terminate the processes from the affected systems ") 
            opt=str(input())
            if (opt=='y' or opt=='Y'):
                for result in results[1]:
                        for systemId, pid in result.items():
                            reaction_id = edrrts.reaction_kill_execution(queryId, systemId, opt_pid)
                            if reaction_id is None:
                                print('ERROR: Could not create new MVISION EDR reaction')
                            while edrrts.reaction_status(reaction_id) is False:
                                print('STATUS: Waiting for 5 seconds to check again.')
                                time.sleep(5)


user_encodedBytes = base64.urlsafe_b64encode(user_name.encode("utf-8"))
encoded_user = str(user_encodedBytes, "utf-8")
pass_encodedBytes = base64.urlsafe_b64encode(user_pass.encode("utf-8"))
encoded_pass = str(pass_encodedBytes, "utf-8")
auth_query = 'https://'+botsink_ip+':'+botsink_port+'/api/auth/login'
credential_json='{"userName":"'+encoded_user+'", "password":"'+encoded_pass+'"}'
auth_http_header=['Content-type: application/json']


parser = argparse.ArgumentParser(description='Option to automate MVEDR and Attivo Investigations')
parser.add_argument('--command', '-c', required=False, type=str, help='Create a case or run a historical search based on Attivo Events use, --edrtype to specify the data type', choices=['CASE', 'SEARCH'])
parser.add_argument('--attivo', '-a', required=True, type=str, help='Search for events, hash or command & control activity', choices=['events', 'adsecurehash','adsecurecc'])
parser.add_argument('--edrtype', '-e', required=False, type=str, help='Must be used alongside --command flag', choices=[
                            'APICall',
                            'ProcessCreated',
                            'PECreated',
                            'NonPECreated',
                            'ArchiveCreated',
                            'ScriptCreated',
                            'ScriptExecuted',
                            'AdminHackingToolExecuted',
                            'ASEPCreatedOrModified',
                            'ServiceChanged',
                            'NetworkConnection',
                            'DNSQuery',
                            'ScheduledTaskRegistered',
                            'LoginLogout',
                            'LoadedDLLs',
                            'UserAccounts',
                            'WMIActivity',
                            'EPP_Response',
                            'DetectionsAlerts',
                            'Alerts'])


args = parser.parse_args()                        


def rest_connect(url,postdata,http_header):
    buffer = BytesIO()
    con_handler = pycurl.Curl()
    con_handler.setopt(con_handler.URL, url)
    con_handler.setopt(con_handler.HTTPHEADER, http_header)
    con_handler.setopt(con_handler.VERBOSE, 0)
    con_handler.setopt(pycurl.SSL_VERIFYPEER, 0)   
    con_handler.setopt(pycurl.SSL_VERIFYHOST, 0)
    con_handler.setopt(pycurl.WRITEFUNCTION, lambda x: None)
    con_handler.setopt(pycurl.POST, 1)
    con_handler.setopt(pycurl.POSTFIELDS, postdata)
    con_handler.setopt(con_handler.WRITEDATA, buffer)
    con_handler.perform()
    con_handler.close()
    response = buffer.getvalue().decode("utf-8")
    return response
    
##Grab Global Session creds from Botsink
rest_response = rest_connect(auth_query,credential_json,auth_http_header)
session_response = json.loads(rest_response)
session_key=session_response["sessionKey"]
events_header = ['Content-type: application/json','Sessionkey:'+session_key]


def adsecure_q (profile_id):
    events_query_url = 'https://'+botsink_ip+':'+botsink_port+'/api/query/fetch'
    data_grab_time=str(attivo_data_grab_time)
    events_post = '{"filter":{"and":[{"field":"querytimeutc","from":"now-'+str(data_grab_time)+'d","to":"now","operator":"<>"},{"field":"acknowledged","value":"false","operator":"="},{"field":"profileid","value":"'+profile_id+'","operator":"="}]},"feature":"ad_secure_queries","size":100,"from":0,"sort":[{"field":"querytimeutc","order":"desc"}]}'
    q_results=json.loads(rest_connect(events_query_url,events_post,events_header))
    return q_results

def adsecure_profile_id ():
    query_url = 'https://'+botsink_ip+':'+botsink_port+'/api/intercept/profile/list?botsinkId=0'
    headers_dict = {"Content-Type":"application/json","sessionKey":session_key}
    response = requests.get(query_url, headers=headers_dict,verify=False)
    ads_profile_id=json.dumps(response.json())
    ads_profile_id=json.loads(ads_profile_id)
    profile_id=None
    i=0
    for each in ads_profile_id["profile_cfg"]:
        if(i==0 or i==1):
            profile_id=str(each["id"])
            profile_name=each["profileName"]
            print ("Found following ADSecure Profiles Name: "+profile_name+" id: "+profile_id)
            i=i+1
        else:
            profile_id=str(each["id"])
            profile_name=each["profileName"]
            print ("Found multiple ADSecure Profiles Name: "+profile_name+" id: "+profile_id+" enter the profile id you want to use")
            profile_id=str(input())

    return profile_id

if(args.attivo=='events'):
    events_query_url = 'https://'+botsink_ip+':'+botsink_port+'/api/eventsquery/alerts'
    data_grab_time=str(attivo_data_grab_time)
    events_post = '{"timestampStart":"now-'+data_grab_time+'d", "timestampEnd":"now"}' 
    q_results=json.loads(rest_connect(events_query_url,events_post,events_header))
    combos=[]
    #print(json.dumps(q_results, indent=4, sort_keys=True))
    for each in q_results["eventdata"]:
        attackdesc_url=urllib.parse.quote_plus(each["attackDesc"].strip())
        attackerHostname=each["attackerHostname"]
        attackName_url=urllib.parse.quote_plus(each["attackName"].strip())
        attackerIP=each["sourceIP"]
        attacker_host_from_dom=each["sourceIPDomain"]
        attacker_host_from_dom=attacker_host_from_dom.partition('.')
        attacker_host_from_dom=attacker_host_from_dom[0]
        target=each["details"]["Target"]
        if(attackerHostname==None):
            attackerHostname=attacker_host_from_dom
        combos.append((attackerIP,attackerHostname,each["attackDesc"],each["attackName"],attackdesc_url,attackName_url))
        
    if(args.command=='CASE'):
        
        if(attackerHostname):
            for combo in combos:
                print ("Attack Detected in Attivo for "+str(combo[1])+" IP "+str(combo[0])+" Description "+str(combo[2])+" "+str(combo[3])+"\n\n")
            print ("Enter a hostname from the list to trigger MVEDR Guided Investigation max 10 per hour")
            opt=str(input())
            if(opt):
                casename=urllib.parse.quote_plus('Attivo Case '+str(datetime.now()))
                device_update=edr_hook+'/AddEvidence?eventSrc=attivo&caseHint='+opt+'&caseType=malware&caseName='+casename+'&caseSummary='+casename+'&evidenceType=Device&hostName='+opt+'&name='+opt
                reqload=requests.get(device_update)
                print(reqload.status_code)
                if(reqload.status_code==200 or reqload.status_code==201):
                    print("MVEDR Guided Investigation created for "+opt)
                else:
                    print ("Error creating Guided Investigation..".reqload.status_code)
    elif(args.command=='SEARCH' and args.edrtype != None):
        	
        if(attackerHostname):
            print ("Attack Detected in Attivo for "+attackerHostname+" IP "+attackerIP+" Description "+each["attackDesc"])
            print ("Do you want to search MFE EDR historical data for "+attackerHostname)
            opt=str(input())
            if(opt=='y' or opt=='Y'):
                edr_data_type=args.edrtype
                edr = EDRHistory(attackerHostname)
                if args.edrtype == 'DetectionsAlerts' or args.edrtype == 'Alerts':
                    result=json.dumps(edr.detect_search())
                    result=json.loads(result)
                    print(json.dumps(result, indent=4, sort_keys=True))
                else:
                    result=json.dumps(edr.hist_search())
                    result=json.loads(result)
                    print(json.dumps(result, indent=4, sort_keys=True))
            else:
                print ("Please choose correct option Y/y to continue ...")
                exit(0)
        else:
            print("Insufficient data in Attivo logs for EDR query")        
    elif(args.command=='SEARCH' and args.edrtype ==None):
        print ("Please specify the edr search type ")
        exit(0)

elif(args.attivo=='adsecurehash'):
    combos=[]
    adsecure_profile_id=adsecure_profile_id()
    q_results=adsecure_q(adsecure_profile_id)
    
    if (q_results["result"]["totalCount"]>0):
        for each in q_results["result"]["adsecure_queries"]:
            combos.append((each["hostname"],each["binaryname"],each["hash"],each["pid"]))
        combos = list(dict.fromkeys(combos))
        for uniq_combo in combos:    
            print ("Found following Attivo Adsecure Reports for Host "+uniq_combo[0]+" "+" Process Name "+uniq_combo[1]+" Hashes "+uniq_combo[2]+" PID "+uniq_combo[3])
        print ("Enter a file hash/process id from the list to query MVEDR")
        opt=str(input())
        if (len(opt)==32 or len(opt)==64 or len(opt)==256):
            edr=EDRRTS()
            queryId = edr.searchhash(uniq_combo[2])
            if queryId is None:
                sys.exit()
            while edr.search_status(queryId) is False:
                time.sleep(10)
                results=edr.search_result(queryId)
                if(results):
                    results_p=json.dumps(results[0])
                    results_p=json.loads(results_p)
                    print(json.dumps(results_p, indent=4, sort_keys=True))
            if(results[1]):
                    print ("Do you want to remove the file from the affected systems ") 
                    opt=str(input())
                    if (opt=='y' or opt=='Y'):
                        if results[1] == []:
                            print('INFO: All Files deleted on Systems')
                            sys.exit()
                        for result in results[1]:
                            for systemId, filePath in result.items():
                                print (systemId,filePath)
                                reaction_id = edr.reaction_removefile_execution(queryId, systemId, filePath)  
                                if reaction_id is None:
                                    print('ERROR: Could not create new MVISION EDR reaction')
                                    while edr.reaction_status(reaction_id) is False:
                                        print('STATUS: Waiting for 5 seconds to check again.')
                                        time.sleep(5)
        else:
            edr_kill_process(opt)                    
    else:
        print ("No Attivo Endpoint processes detected ")                                    
elif(args.attivo=='adsecurecc'):
    adsecure_profile_id=adsecure_profile_id()
    q_results=adsecure_q(adsecure_profile_id)
    combos=[]
    if (q_results["result"]["totalCount"]>0):
        for each in q_results["result"]["adsecure_queries"]:
            combos.append((each["pid"],each["hostname"],each["binaryname"]))
        combos = list(dict.fromkeys(combos))
        for uniq_combo in combos:    
            print ("Do you want to search EDR for C&C Activity around Process ID: "+uniq_combo[0]+" Hostname "+uniq_combo[1]+" Name: "+uniq_combo[2])
        print ("Enter a process ID to look for Network Connections ")
        opt_pid=str(input())
        if (opt_pid.isnumeric):
            edrrts=EDRRTS()
            queryId = edrrts.search_network(opt_pid)
            if queryId is None:
                sys.exit()
            while edrrts.search_status(queryId) is False:
                time.sleep(10)
                results = edrrts.search_result_network(queryId)
                
                result_json=json.dumps(results[0])
                result_json=json.loads(result_json)
                print(json.dumps(result_json, indent=4, sort_keys=True))
                
                if(results[1]):
                    print ("Do you want to terminate the processes from the affected systems ") 
                    opt=str(input())
                    if (opt=='y' or opt=='Y'):
                        for result in results[1]:
                                for systemId, pid in result.items():
                                    reaction_id = edrrts.reaction_kill_execution(queryId, systemId, opt_pid)
                                    if reaction_id is None:
                                        print('ERROR: Could not create new MVISION EDR reaction')
                                    while edrrts.reaction_status(reaction_id) is False:
                                        print('STATUS: Waiting for 5 seconds to check again.')
                                        time.sleep(5)
            else:
                print ("Enter valid process id")
    else:
        print ("No Attivo Endpoint processes detected ")                        
else:
    print ("Check valid option combinations")

