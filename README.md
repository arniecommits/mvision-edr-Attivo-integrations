# mvision-edr-Attivo-integrations
 These are some sample API integration patterns between Attivo's Deception Fabric and MV EDR
The idea here is simple, Attivo's Botsink solution detects a threat and MVISION EDR provides rich data , context and response actions to the high fidelity detection from Attivo.

Please fill in the following connection details in the script before executing 

botsink_ip='10.1.0.4'
botsink_port='8443'
user_name='botsink_api_user'
user_pass='botsink_pass'
#Historical data search duration
edr_data_grab_time=7
attivo_data_grab_time=7
#url generated from the integrations page in MVEDR
edr_hook='https://api.soc.ap-southeast-2.mcafee.com/wh/v1/webhook/<hookid>'
edr_user='edruser'
edr_pass='edrpass'
edr_region='SY'
#number of records to use from edr
edr_limit = '50'

The script can be invoked as follows

usage: attivomfe.py [-h] [--command {CASE,SEARCH}] --attivo {events,adsecurehash,adsecurecc}
                    [--edrtype {APICall,ProcessCreated,PECreated,NonPECreated,ArchiveCreated,ScriptCreated,ScriptExecuted,AdminHackingToolExecuted,ASEPCreatedOrModified,ServiceChanged,NetworkConnection,DNSQuery,ScheduledTaskRegistered,LoginLogout,LoadedDLLs,UserAccounts,WMIActivity,EPP_Response,DetectionsAlerts,Alerts}]

Option to automate MVEDR and Attivo Investigations

optional arguments:
  -h, --help            show this help message and exit
  --command {CASE,SEARCH}, -c {CASE,SEARCH}
                        Create a case or run a historical search based on Attivo Events use, --edrtype to specify the data type
  --attivo {events,adsecurehash,adsecurecc}, -a {events,adsecurehash,adsecurecc}
                        Search for events, hash or command & control activity
  --edrtype {APICall,ProcessCreated,PECreated,NonPECreated,ArchiveCreated,ScriptCreated,ScriptExecuted,AdminHackingToolExecuted,ASEPCreatedOrModified,ServiceChanged,NetworkConnection,DNSQuery,ScheduledTaskRegistered,LoginLogout,LoadedDLLs,UserAccounts,WMIActivity,EPP_Response,DetectionsAlerts,Alerts}, -e {APICall,ProcessCreated,PECreated,NonPECreated,ArchiveCreated,ScriptCreated,ScriptExecuted,AdminHackingToolExecuted,ASEPCreatedOrModified,ServiceChanged,NetworkConnection,DNSQuery,ScheduledTaskRegistered,LoginLogout,LoadedDLLs,UserAccounts,WMIActivity,EPP_Response,DetectionsAlerts,Alerts}
                        Must be used alongside --command flag
