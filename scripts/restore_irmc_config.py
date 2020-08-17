#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to restore iRMC settings via iRMC Redfish API
  in Fujitsu PRIMERGY

  [Usage]
  - Restore iRMC settings from a file
  $ python restore_irmc_config.py -i 192.168.10.10 -u admin -p admin -f irmc.pre
  
"""
import sys
import time
import argparse
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"


def restore_irmc_config(irmc, user, password, irmc_config):
    # Create a session
    session = requests.Session()
    session.verify = False
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json'}
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
    session.headers.update({"X-Auth-Token": response.headers["X-Auth-Token"]})
    session_info = response.headers['Location']
    
    # Send a restore request
    url = "https://{}/redfish/v1/Managers/iRMC/Actions/Oem/FTSManager.ImportConfiguration".format(
        irmc)
    payload = {'data': open(irmc_config, 'r')}
    response = session.post(url, files=payload)

    if response.status_code != 202:
        print("ERROR: The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        session.delete("https://{0}{1}".format(irmc, session_info))
        sys.exit()

    task_url = "https://{0}{1}".format(irmc, response.headers['Location'])

    max_wait_time = 60
    while max_wait_time:
        response = session.get(task_url)
        #progress = response_data['Oem']['ts_fujitsu']['TotalProgressPercent']

        if response.json()['TaskState'] == "Completed":
            print("iRMC Restore has been completed successfully.")
            break
        #else:
        #    print("Progress: {}%".format(progress))
        
        # check the task status every second
        time.sleep(1)
        max_wait_time -= 1

    if max_wait_time == 0:
        print("ERROR: iRMC Restore did not complete in time.")

    session.delete("https://{0}{1}".format(irmc, session_info))


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
        help="iRMC configuration file name"
    )

    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    irmc_config = args.file

    restore_irmc_config(irmc, user, password, irmc_config)


if __name__ == '__main__':
    main()
