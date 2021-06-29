#!/usr/bin/env python3
import pycurl, base64, json, requests, urllib.parse, time,sys, argparse, subprocess, logging,re,os
from io import BytesIO
from mcafee_epo import Client
from argparse import ArgumentParser, RawTextHelpFormatter
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings("ignore")

###Fill Attivo Botsink Connection details
botsink_ip='10.1.0.4'
botsink_port='8443'
user_name='api'
user_pass=''
attivo_data_grab_time='1d'


class EPO():
    def __init__(self):
##Fill in ePO Connection details        
        self.epo_ip = '10.1.40.51'
        self.epo_port = '8443'
        self.epo_verify = False
        self.epo_user = 'admin'
        self.epo_pw = ''
        self.session = requests.Session()

        
    
    def request(self, option, **kwargs):
        try:
            kwargs.setdefault('auth', (self.epo_user, self.epo_pw))
            kwargs.setdefault('verify', self.epo_verify)
            kwargs.setdefault('params', {})
            kwargs['params'][':output'] = 'json'
            
            url = 'https://{0}:{1}/remote/{2}'.format(self.epo_ip, self.epo_port, option)
            
            if kwargs.get('data') or kwargs.get('json') or kwargs.get('files'):
                res = self.session.post(url, **kwargs)
            else:
                res = self.session.get(url, **kwargs)
            if res.ok and res.text.startswith('OK:'):
                data = json.loads(res.text[3:])
                return data, res.status_code, res
                     
        except Exception as error:
            raise BaseException(error)


    def request_event(self, option, **kwargs):
        try:
            kwargs.setdefault('auth', (self.epo_user, self.epo_pw))
            kwargs.setdefault('verify', self.epo_verify)
            kwargs.setdefault('params', {})
            kwargs['params'][':output'] = 'json'
            
            url = 'https://{0}:{1}/remote/{2}'.format(self.epo_ip, self.epo_port, option)
            
            if kwargs.get('data') or kwargs.get('json') or kwargs.get('files'):
                res = self.session.post(url, **kwargs)
                return res.status_code
            else:
                res = self.session.get(url, **kwargs)
                     
        except Exception as error:
            raise BaseException(error)



    def event_model(self):
        with open(os.path.join(os.path.dirname(__file__), 'attivo_event.json')) as data_file:
            data = json.load(data_file)
        return data        

class Attivo():

    def rest_connect(self,url,postdata,http_header):
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
    
    def auth(self):
        user_encodedBytes = base64.urlsafe_b64encode(user_name.encode("utf-8"))
        encoded_user = str(user_encodedBytes, "utf-8")
        pass_encodedBytes = base64.urlsafe_b64encode(user_pass.encode("utf-8"))
        encoded_pass = str(pass_encodedBytes, "utf-8")
        auth_query = 'https://'+botsink_ip+':'+botsink_port+'/api/auth/login'
        credential_json='{"userName":"'+encoded_user+'", "password":"'+encoded_pass+'"}'
        auth_http_header=['Content-type: application/json']
        rest_response = self.rest_connect(auth_query,credential_json,auth_http_header)
        session_response = json.loads(rest_response)
        session_key=session_response["sessionKey"]
        events_header = ['Content-type: application/json','Sessionkey:'+session_key]
        return session_key

    def adsecure_profile_id (self):
        query_url = 'https://'+botsink_ip+':'+botsink_port+'/api/intercept/profile/list?botsinkId=0'
        session_key=self.auth()
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

    def adsecure_events (self):
        events_query_url = 'https://'+botsink_ip+':'+botsink_port+'/api/query/fetch'
        data_grab_time=str(attivo_data_grab_time)
        profile_id=self.adsecure_profile_id()
        events_post = '{"filter":{"and":[{"field":"querytimeutc","from":"now-'+str(data_grab_time)+'","to":"now","operator":"<>"},{"field":"acknowledged","value":"false","operator":"="},{"field":"profileid","value":"'+profile_id+'","operator":"="}]},"feature":"ad_secure_queries","size":100,"from":0,"sort":[{"field":"querytimeutc","order":"desc"}]}'
        session_key=self.auth()
        events_header = ['Content-type: application/json','Sessionkey:'+session_key]
        q_results=json.loads(self.rest_connect(events_query_url,events_post,events_header))
        return q_results 


    def attivo_events(self):
        events_query_url = 'https://'+botsink_ip+':'+botsink_port+'/api/eventsquery/alerts'
        data_grab_time=str(attivo_data_grab_time)
        events_post = '{"timestampStart":"now-'+data_grab_time+'", "timestampEnd":"now"}'
        session_key=self.auth()
        events_header = ['Content-type: application/json','Sessionkey:'+session_key] 
        q_results=json.loads(self.rest_connect(events_query_url,events_post,events_header))
        return q_results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Option to automate Attivo and ePO Logs Integration')
    parser.add_argument('--command', '-c', required=True, type=str, help='specify which events from Attivo you want to send to ePO', choices=['events', 'adsecure'])
    parser.add_argument('--duration', '-d', required=False, type=str, help='specify which sync duration in minutes, days 1m,1d etc ')
    args = parser.parse_args()  
    epo = EPO()
    attivo=Attivo()
    
    def send_adsecure():
        
        attivo_logs=attivo.adsecure_events()
        
        if (attivo_logs["result"]["totalCount"]>0):
            event_data = epo.event_model()
            for each in attivo_logs["result"]["adsecure_queries"]:
                hostName=each["hostname"]
                machine_information, code, msg = epo.request('system.find', data={'searchText': hostName})
                #print (machine_information)
                if(code==200):
                    event_data["event"]["entity"]["osPlatform"] = machine_information[0]["EPOComputerProperties.OSPlatform"]
                    event_data["event"]["entity"]["osType"] = machine_information[0]["EPOComputerProperties.OSType"]
                    event_data["event"]["analyzer"]["hostName"] = machine_information[0]["EPOComputerProperties.ComputerName"]
                    event_data["event"]["analyzer"]["ipv4"] = machine_information[0]["EPOComputerProperties.IPAddress"]
                    event_data["event"]["analyzer"]["ipv6"] = machine_information[0]["EPOComputerProperties.IPV6"]
                    event_data["event"]["analyzer"]["mac"] = machine_information[0]["EPOComputerProperties.NetAddress"]
                    event_data["event"]["source"]["hostName"] = machine_information[0]["EPOComputerProperties.ComputerName"]
                    event_data["event"]["source"]["ipv4"] = machine_information[0]["EPOComputerProperties.IPAddress"]
                    event_data["event"]["source"]["ipv6"] = machine_information[0]["EPOComputerProperties.IPV6"]
                    event_data["event"]["source"]["userName"] = machine_information[0]["EPOComputerProperties.UserName"]
                    event_data["event"]["source"]["mac"] = machine_information[0]["EPOComputerProperties.NetAddress"]
                    event_data["event"]["target"]["hostName"] = machine_information[0]["EPOComputerProperties.ComputerName"]
                    event_data["event"]["target"]["ipv4"] = machine_information[0]["EPOComputerProperties.IPAddress"]
                    event_data["event"]["target"]["ipv6"] = machine_information[0]["EPOComputerProperties.IPV6"]
                    event_data["event"]["target"]["userName"] = machine_information[0]["EPOComputerProperties.UserName"]
                    event_data["event"]["target"]["mac"] = machine_information[0]["EPOComputerProperties.NetAddress"]
                    event_data["event"]["entity"]["id"] = machine_information[0]["EPOLeafNode.AgentGUID"]
                    event_data["event"]["_receivedUTC"] = each["querytimeutc"]
                    event_data["event"]["threatName"] = each["binaryname"]
                    event_data["event"]["eventDesc"] = each["queryData"]
                    event_data["event"]["analyzer"]["detectionMethod"] = "Attivo ADSECURE"
                    event_data["event"]["analyzer"]["name"] = "Attivo ADSECURE"
                    event_data["event"]["analyzer"]["id"] = "ATTIVO" 
                    event_data["event"]["eventId"] = 2010 
                    event_data["event"]["category"] = "Attivo Report"
                    event_data["event"]["threatType"] = "ADSECURE Detection"
                    event_data["event"]["eventMsgType"] = "Attivo AD Secure Report"
                    event_data["event"]["source"]["processName"] = each["arguments"]
                    event_data["event"]["target"]["fileName"] = each["processpath"]
                    event_data["event"]["target"]["processName"] = each["processname.raw"]
                    event_data["event"]["analyzer"]["detectedUTC"] = each["insertTime"]
                    event_data["event"]["files"][0]["name"] = each["originalfilename"]
                    event_data["event"]["files"][0]["hash"]["SHA-256"] = each["hash"]
                    event_data["event"]["files"][0]["hash"]["MD5"] = 'bf9ea75bd1d06d64c834e63a7e1ef0cf'              
                    update=json.dumps(event_data)
                    status=epo.request_event('DxlBrokerMgmt.createEpoThreatEvent', data={'event': update})
                    print (update)
                    

    def send_event_logs():
        attivo_logs=attivo.attivo_events()
        event_data = epo.event_model()
        for each in attivo_logs["eventdata"]:
            attackdesc=each["attackDesc"]
            attackerHostname=each["attackerHostname"]
            attackName=each["attackName"]
            attackerIP=each["sourceIP"]
            target=each["details"]["Target"]
            mitre=each["details"]["mitre_tech"]
            attackid=each["attackID"]
            severity_verb=each["details"]["Severity"]
            if severity_verb == "High":
                severity=2
            elif severity_verb == "Medium":
                severity=1
            else:
                severity=0    
            timestamp=each["details"]["Timestamp"]
            
            if (attackerHostname is not None):
                machine_information, code, msg = epo.request('system.find', data={'searchText': attackerHostname})
                if(code==200):
                    event_data["event"]["entity"]["osPlatform"] = machine_information[0]["EPOComputerProperties.OSPlatform"]
                    event_data["event"]["entity"]["osType"] = machine_information[0]["EPOComputerProperties.OSType"]
                    event_data["event"]["analyzer"]["hostName"] = machine_information[0]["EPOComputerProperties.ComputerName"]
                    event_data["event"]["analyzer"]["ipv4"] = machine_information[0]["EPOComputerProperties.IPAddress"]
                    event_data["event"]["analyzer"]["ipv6"] = machine_information[0]["EPOComputerProperties.IPV6"]
                    event_data["event"]["analyzer"]["mac"] = machine_information[0]["EPOComputerProperties.NetAddress"]
                    event_data["event"]["source"]["hostName"] = machine_information[0]["EPOComputerProperties.ComputerName"]
                    event_data["event"]["source"]["ipv4"] = machine_information[0]["EPOComputerProperties.IPAddress"]
                    event_data["event"]["source"]["ipv6"] = machine_information[0]["EPOComputerProperties.IPV6"]
                    event_data["event"]["source"]["userName"] = machine_information[0]["EPOComputerProperties.UserName"]
                    event_data["event"]["source"]["mac"] = machine_information[0]["EPOComputerProperties.NetAddress"]
                    event_data["event"]["target"]["hostName"] = machine_information[0]["EPOComputerProperties.ComputerName"]
                    event_data["event"]["target"]["ipv4"] = machine_information[0]["EPOComputerProperties.IPAddress"]
                    event_data["event"]["target"]["ipv6"] = machine_information[0]["EPOComputerProperties.IPV6"]
                    event_data["event"]["target"]["userName"] = machine_information[0]["EPOComputerProperties.UserName"]
                    event_data["event"]["target"]["mac"] = machine_information[0]["EPOComputerProperties.NetAddress"]
                    event_data["event"]["entity"]["id"] = machine_information[0]["EPOLeafNode.AgentGUID"]
                    event_data["event"]["_receivedUTC"] = timestamp
                    event_data["event"]["threatName"] = attackName
                    event_data["event"]["eventName"] = attackdesc
                    event_data["event"]["eventId"] = 2017 
                    event_data["event"]["source"]["processName"] = attackdesc
                    event_data["event"]["threatSeverity"] = severity
                    event_data["event"]["category"] = "Attivo Threat Event"
                    event_data["event"]["threatType"] = str(mitre)
                    event_data["event"]["analyzer"]["detectionMethod"] = "Attivo ADSECURE"
                    event_data["event"]["analyzer"]["name"] = "Attivo ADSECURE"
                    event_data["event"]["analyzer"]["id"] = "ATTIVO"  
                    event_data["eventMsgType"] = "Attivo Log Alert"
                    event_data["event"]["target"]["fileName"] = attackdesc
                    event_data["event"]["target"]["processName"] = attackdesc
                    event_data["event"]["analyzer"]["detectedUTC"] = timestamp              
                    update=json.dumps(event_data)
                    status=epo.request_event('DxlBrokerMgmt.createEpoThreatEvent', data={'event': update})
                    print (update)
    if(args.duration):
        attivo_data_grab_time=args.duration
    if (args.command=='events'):
        send_event_logs()
    if(args.command=='adsecure'):
        send_adsecure()
    
