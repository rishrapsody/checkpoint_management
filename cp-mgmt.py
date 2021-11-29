#!/usr/local/bin/python

import requests,json
import urllib3
urllib3.disable_warnings()
from pprint import pprint
from prettytable import PrettyTable
from tabulate import tabulate
import pandas as pd
from decouple import config

def api_call(ip_addr, port, command, json_payload, sid):
    url = 'https://' + ip_addr + '/web_api/' + command
    if sid == '':
        request_headers = {'Content-Type' : 'application/json'}
        r = requests.post(url, data=json.dumps(json_payload), headers=request_headers, verify=False)
    else:
        request_headers = {'Content-Type' : 'application/json', 'X-chkp-sid' : sid}
        r = requests.post(url, data=json.dumps(json_payload), headers=request_headers, verify=False)
    return r.json()

def login(user,password,domain):
    if domain == None or domain == '':
        payload = {'user':user, 'password' : password}
    else:
        payload = {'user': user, 'password': password, 'domain': domain}
    response = api_call('192.168.251.5', 443, 'login',payload, '')
    return response["sid"]

def main():
    print("Logging in..")
#    passwd = os.getenv('cp_password')
    passwd = config('cp_password')
    sid = login('rishabh',passwd,'')
    print("session id: " + sid)
    payload = { "limit" : 50, "offset" : 0, "details-level" : "full"}
    get_domains = api_call('192.168.251.5', 443, 'show-domains', payload, sid)
 #   pprint(get_domains)
    PrettyTable.field_names=["ID","Domain","Mgmt_Server","Log_Server"]
    global tlist
    tlist = []
    for i,domain in enumerate(get_domains['objects'],start=1):
        t = len(domain['servers'])
 #       print(t)
        for j in range(len(domain['servers'])):
            j=j+1
            if domain['servers'][j-1]['type'] == "management server" and len(domain['servers']) > 1:
                mgmt_server = domain['servers'][j-1]['ipv4-address']
                log_server = domain['servers'][t-j]['ipv4-address']
            else:
                mgmt_server = domain['servers'][0]['ipv4-address']
                log_server = "Not Configured"
  #      print("{} :: {} , Mgmt_Server {}, Log_Server {}".format(i,domain['name'],mgmt_server, log_server))
        list1 = []
        list1 = [i, domain['name'], mgmt_server, log_server]
        tlist.append(list1)
    print(tabulate(tlist, headers=['ID','Domain', 'Mgmt Server', 'Log Server']))
    df=pd.DataFrame(tlist)
    df.to_csv('Domains-list.csv',header=['ID','Domain', 'Mgmt Server', 'Log Server'],index=False)
    get_gtwy()

def get_gtwy():
    payload = {"limit": 50, "offset": 0, "details-level": "full"}
    for ilist in tlist:
        domain = ilist[1]
        sid = login('rishabh', 'parihar@16', domain)
        simple_gateway = api_call(ilist[2],"443","show-simple-gateways",payload,sid)
#        pprint(simple_gateway)
        print("#" * 40)
        g_list = []
        print("Domain: {}".format(ilist[1]))
        gtwy_grp = simple_gateway['objects']
        print("*Standalone:{}*".format(len(gtwy_grp)))
        for i in gtwy_grp:
#            print(i['name'])
            temp_list = [i['ipv4-address'],i['name'],i['sicExists']]
            g_list.append(temp_list)
        print(tabulate(g_list, headers=["IPv4","Gateway","sicExists"]))
        if len(gtwy_grp) > 0:
            df = pd.DataFrame(g_list)
            df.to_csv('{}-Standalone.csv'.format(domain), header=["IPv4","Gateway","sicExists"], index=False)
        print("")
        c_list = []
        simple_cluster = api_call(ilist[2], "443", "show-simple-clusters", payload, sid)
#        pprint(simple_cluster)
        clstr_grp = simple_cluster['objects']
        print("*Cluster:{}*".format(len(clstr_grp)))
        for i in clstr_grp:
#            print(i['name'])
            temp_list = [i['ipv4-address'],i['name'],i['cluster-members'][0]['name'],i['cluster-members'][0]['ip-address'],i['cluster-members'][1]['name'],i['cluster-members'][1]['ip-address'],i['anti-bot'],i['anti-virus'],i['application-control'],i['content-awareness'],i['url-filtering'],i['vpn']]
            c_list.append(temp_list)
        print(tabulate(c_list, headers=["IPv4","Cluster","Member1","IP1","Member2","IP2","Anti-Bot","Anti-Virus","App-Ctrl","Content","Url-F","VPN"]))
        if len(clstr_grp) > 0:
            df = pd.DataFrame(c_list)
            df.to_csv('{}-Cluster.csv'.format(domain), header=["IPv4","Cluster","Member1","IP1","Member2","IP2","Anti-Bot","Anti-Virus","App-Ctrl","Content","Url-F","VPN"], index=False)
        print("")
        print("#" * 40)



if __name__ == "__main__":
    main()

