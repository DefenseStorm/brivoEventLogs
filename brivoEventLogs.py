#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests
import time
from datetime import datetime
from datetime import timedelta
import base64

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

from html.parser import HTMLParser

class integration(object):

    audit_JSON_field_mappings = {
        'occurred' : 'timestamp'
    }

    access_JSON_field_mappings = {
        'occurred' : 'timestamp'
    }

    def brivo_basicAuth(self):
        url = self.auth_url + '/oauth/token'
        self.ds.log('INFO', "Attempting basic auth to  url: " + url)
        auth_string = self.client_id + ':' + self.client_secret
        auth_string.encode()
        params = {
                'api-key': self.api_key,
                'Content-type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic ' + (base64.b64encode(auth_string.encode())).decode('ascii')
                }
        data = {
                'grant_type': 'password',
                'username': self.username,
                'password': self.password
                }
        try:
            response = requests.post(url, headers = params, data = data)
        except Exception as e:
            self.ds.log('ERROR', "Exception in brivo_request: {0}".format(str(e)))
            traceback.print_exc()
            return None
        if not response or response.status_code != 200:
            self.ds.log('ERROR', "Received unexpected " + str(response) + " response from Brivo Server {0}.".format(url))
            self.ds.log('ERROR', "Exiting due to unexpected response.")
            sys.exit(0)
        if response == None and response.headers == None:
            return None
        r_json = response.json()
        access_token = r_json['access_token']
        refresh_token = r_json['refresh_token']
        headers = response.headers
        return access_token

    def brivo_getEvents(self, event_type):
        pagesize = 100
        total_events = []
        params = {
                'pageSize': pagesize,
                'filter': 'occurred__gt:' + self.last_run + ';occurred__lt:' + self.current_run,
            }
        response = self.brivo_request('/v1/api/events/counts/' + event_type, params = params)
        r_json = response.json()
        record_count = r_json['count']
        if record_count == 0:
            self.ds.log('INFO', "No %s events to retreive: " %(event_type))
            return
        self.ds.log('INFO', "Retreiving %d %s events: " %(record_count, event_type))
        response = self.brivo_request('/v1/api/events/' + event_type, params = params)
        r_json = response.json()
        events = r_json['data']
        if len(events) == 0:
            return events
        total_events += events
        highest_date = events[0]['occurred']
        while record_count > len(total_events):
            for event in events:
                if event['occurred'] < highest_date:
                    highest_date = event['occurred']
            params = {
                'offset': highest_date,
                'pageSize': pagesize,
                'filter': 'occurred__gt:' + self.last_run + ';occurred__lt:' + self.current_run,
                }
            response = self.brivo_request('/v1/api/events/' + event_type, params = params)
            r_json = response.json()
            events = r_json['data']
            total_events += events
        return total_events


    def brivo_request(self, path, params = None, verify=False, proxies=None):
        url = self.api_url + path
        headers = {
                'api-key': self.api_key,
                'Authorization': 'bearer ' + self.token
            }
        self.ds.log('INFO', "Attempting to connect to url: " + url + " with params: " + json.dumps(params))
        try:
            response = requests.get(url, headers=headers, params = params, timeout=15,
                                    verify=verify, proxies=proxies)
        except Exception as e:
            self.ds.log('ERROR', "Exception in brivo_request: {0}".format(str(e)))
            return None
        if not response or response.status_code != 200:
            self.ds.log('ERROR', "Received unexpected " + str(response.text) + " response from Brivo Server {0}.".format(url))
            self.ds.log('ERROR', "Exiting due to unexpected response.")
            sys.exit(0)
        return response



    def brivo_main(self): 

        self.auth_url = self.ds.config_get('brivo', 'auth_url')
        self.api_url = self.ds.config_get('brivo', 'api_url')
        self.state_dir = self.ds.config_get('brivo', 'state_dir')
        self.last_run = self.ds.get_state(self.state_dir)
        self.client_id = self.ds.config_get('brivo', 'client_id')
        self.client_secret = self.ds.config_get('brivo', 'client_secret')
        current_time = datetime.utcnow()
        if self.last_run == None:
            self.last_run = (current_time - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.current_run = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        self.username = self.ds.config_get('brivo', 'username')
        self.password = self.ds.config_get('brivo', 'password')
        self.api_key = self.ds.config_get('brivo', 'api_key')
        self.token = self.brivo_basicAuth()
        print(self.token)
        if self.token != None and self.get_token == True:
            print("Token - " + self.token)
            return None

        if self.token == None or self.token == '':
            self.ds.log('ERROR', "Invalid Configuration or auth failed.  No token available")
            return None


        audit_events = self.brivo_getEvents('audit')
        access_events = []
        access_events = self.brivo_getEvents('access')

        if audit_events == None:
            self.ds.log('INFO', "There are no event logs to send")
        else:
            self.ds.log('INFO', "Sending {0} event logs".format(len(audit_events)))
            for log in audit_events:
                log['category'] = 'audit-events'
                if 'actor' in  log.keys():
                    log['message'] = log['securityAction']['action'] + ' - ' + log['actor']['name']
                else:
                    log['message'] = log['securityAction']['action']
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.audit_JSON_field_mappings, flatten = False)

        if access_events == None:
            self.ds.log('INFO', "There are no system event logs to send")
        else:
            self.ds.log('INFO', "Sending {0} system event logs".format(len(access_events)))
            for log in access_events:
                log['category'] = "access-events"
                message = log['securityAction']['action'] + ' - ' + log['eventObject']['name']
                if 'actor' in log.keys() and 'name' in log['actor'].keys():
                    message += ' - ' + log['actor']['name']
                log['message'] = message
                log['action'] = log['securityAction']['action']
                log['username'] = log['actor']['name']
                log['location'] = log['site']['siteName']
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.access_JSON_field_mappings)


        self.ds.set_state(self.state_dir, self.current_run)
        self.ds.log('INFO', "Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('brivo', 'pid_file')
            fp = open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance of cb defense syslog connector is already running")
                # another instance is running
                sys.exit(0)
            self.brivo_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print
        print(os.path.basename(__file__))
        print
        print('  No Options: Run a normal cycle')
        print
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print
        print('  -l    Log to stdout instead of syslog Local6')
        print
        print('  -g    Authenticate to Get Token then exit')
        print
    
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
        self.get_token = None
    
        try:
            opts, args = getopt.getopt(argv,"htlg")
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
            elif opt in ("-g"):
                self.get_token = True
    
        try:
            self.ds = DefenseStorm('brivoEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
