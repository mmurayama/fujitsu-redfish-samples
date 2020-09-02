#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to download a PrimeCollect via iRMC Redfish API
  in Fujitsu PRIMERGY

  [Note]
  This requires an iRMC eLCM license. 

  [Usage]
  - Download a PrimeCollect
  $ python download_primecollect.py -i 192.168.10.10 -u admin -p admin

"""
import sys
import time
import datetime
import json
import argparse
import requests
import urllib3
from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"

def send_request(session, url, method, *data):
    response = None
    if method == 'GET':
        response = session.get(url)
    elif method == 'POST':
        if data is not None:
            response = session.post(url, data=data[0])
        else:
            response = session.post(url)
    elif method == 'DELETE':
            response = session.delete(url)

    domain = urlparse(url).netloc
    if response.status_code != 200 and response.status_code != 202 and response.status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        session.delete('https://{}{}'.format(domain, session.headers['Location']))
        sys.exit()
    
    return response


def download_primecollect(irmc, user, password):
    session = requests.Session()
    session.verify = False
    headers = {'Content-Type': 'application/json'}
    payload = {'UserName': user, 'Password': password}
    sessions_url = "https://{}/redfish/v1/SessionService/Sessions".format(irmc)
    response = session.post(
        sessions_url,
        headers=headers,
        auth=(user, password),
        data=json.dumps(payload)
    )
    if response.status_code != 201:
        print("ERROR: Could not create a session for the iRMC")
        sys.exit()
    session.headers.update({
        'X-Auth-Token': response.headers['X-Auth-Token'], 
        'Accept': 'application/json,application/octet-stream', 
        'Content-Type': 'application/json',
        'Location': response.headers['Location']
    })

    # iRMC S4 FW < 9.60F does not support eLCM and SDCard endpoints
    response = send_request(session, 'https://{}/redfish/v1/Managers/iRMC'.format(irmc), 'GET')
    irmc_fw = response.json()['FirmwareVersion']
    irmc_model = response.json()['Model']

    if irmc_model == 'iRMC S4' and int(irmc_fw[0:-1].replace('.','')) < 960:
        print("ERROR: The PrimeCollect endpoint is not supported in {} firmware {}.".format(irmc_model, irmc_fw))
        session.delete("https://{0}{1}".format(irmc, session.headers['Location']))
        sys.exit()

    # Check if eLCM is licensed
    response = send_request(session, 'https://{}/redfish/v1/Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Licenses'.format(irmc), 'GET')

    for key in response.json()['Keys']:
        if key['Name'] == 'eLCM':
            if key['Type'] != 'Permanent' and key['Type'] != 'Temporary':
                print("ERROR: eLCM license key is not installed.")
                session.delete("https://{0}{1}".format(irmc, session.headers['Location']))
                sys.exit()

    # Check if an SD card is ready
    response = send_request(session, 'https://{}/redfish/v1/Systems/0/Oem/ts_fujitsu/SDCard'.format(irmc), 'GET')

    if response.json()['Status'] != 'OK':
        print("ERROR: SDCard is not available/ready.")        
        session.delete("https://{0}{1}".format(irmc, session.headers['Location']))
        sys.exit()

    # Check if ServerView Agent/Agentless Service is running in the OS
    response = send_request(session, 'https://{}/redfish/v1/Systems/0/Oem/ts_fujitsu/System'.format(irmc), 'GET')

    if response.json()['AgentConnected'] != True:
        print("ERROR: ServerView Agent/Agentless Servie is not running in the OS.")
        session.delete("https://{0}{1}".format(irmc, session.headers['Location']))
        sys.exit()        

    # Generate a PrimeCollect archive
    payload = { 
        'ExecutionMode': 'Generate',
        'SchedulingType': 'Immediately' 
    }
    url = "https://{}/redfish/v1/Systems/0/Oem/ts_fujitsu/eLCM/PrimeCollect/Actions/FTSPrimeCollect.TriggerArchiveGeneration".format(irmc)
    response = send_request(session, url, 'POST', json.dumps(payload))

    task_url = "https://{0}{1}".format(irmc, response.headers['Location'])

    # Will wait for up to 180 seconds for the task to be completed
    max_wait_time = 180
    while max_wait_time:
        response = send_request(session, task_url, 'GET')

        if response.json()['TaskState'] == "Completed":
            break
        else:
            print("Generating a PrimeCollect. Please wait... (elapsed: {} seconds)".format(str(180 - max_wait_time)), end='\r')
        
        # check the task status every second
        time.sleep(1)
        max_wait_time -= 1

    if max_wait_time == 0:
        print("\nERROR: Generating a PrimeCollect did not complete in time. Please check the task log at {}/Oem/ts_fujitsu/Logs".format(task_url))
        sys.exit()
    else:
        url = "https://{}/redfish/v1/Systems/0/Oem/ts_fujitsu/eLCM/PrimeCollect".format(irmc)
        response = send_request(session, url, 'GET')
        
        primecollect_list = response.json()['AvailableArchives']

        latest_pc_name = ''
        latest_pc_date = None
        for pc in primecollect_list:
            if latest_pc_date is None:
                latest_pc_date = datetime.datetime.strptime(pc['CreationTime'], '%a %b %d %H:%M:%S %Y')
                latest_pc_name = pc['Name']
            else:
                tmp_date = datetime.datetime.strptime(pc['CreationTime'], '%a %b %d %H:%M:%S %Y')

                if tmp_date > latest_pc_date:
                    latest_pc_date = tmp_date
                    latest_pc_name = pc['Name']

        # Download the archive from iRMC
        url = 'https://{}/redfish/v1/Systems/0/Oem/ts_fujitsu/eLCM/PrimeCollect/Actions/FTSPrimeCollect.DownloadArchive'.format(irmc)
        payload = {'ArchiveName': latest_pc_name}

        response = send_request(session, url, 'POST', json.dumps(payload))

        with open(latest_pc_name, 'wb') as primecollect:
            primecollect.write(response.content)

        print("\nSaved a PrimeCollect as {} successfully.".format(latest_pc_name))
    session.delete("https://{0}{1}".format(irmc, session.headers['Location']))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i', '--irmc',
        required=True,
        help="iRMC IP address/hostname/FQDN")
    parser.add_argument(
        '-u', '--user',
        default="admin",
        help="iRMC user name")
    parser.add_argument(
        '-p', '--password',
        default="admin",
        help="iRMC password")
    parser.add_argument(
        '-f', '--file',
        default="LogArchive.zip",
        help="iRMC log archive file name")

    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password

    download_primecollect(irmc, user, password)


if __name__ == '__main__':
    main()
