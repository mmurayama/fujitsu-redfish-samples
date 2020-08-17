#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to restore BIOS settings via iRMC Redfish API
  in Fujitsu PRIMERGY

  [Usage]
  - Restore BIOS settings from a file
  $ python restore_bios_config.py -i 192.168.10.10 -u admin -p admin -f bios.pre
  
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


def restore_bios_config(irmc, user, password, bios_config):
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

    # Check the current power status
    response = session.get('https://%s/redfish/v1/Systems/0/' % irmc)
    current_power_state = response.json()['PowerState']

    if current_power_state == 'On':
        print("Please shut down the system before sending a restore request.")
        session.delete("https://{0}{1}".format(irmc, session_info))
        sys.exit()
    
    # Send a restore request
    url = "https://{}/redfish/v1/Systems/0/Bios/Actions/Oem/FTSBios.BSPBRRestore".format(
        irmc)
    payload = {'data': open(bios_config, 'r')}
    response = session.post(url, files=payload)

    if response.status_code != 202:
        print("ERROR: The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        session.delete("https://{0}{1}".format(irmc, session_info))
        sys.exit()

    task_url = "https://{0}{1}".format(irmc, response.headers['Location'])

    while True:
        response = session.get(task_url)
        response_data = response.json()
        state = response_data['TaskState']
        progress = response_data['Oem']['ts_fujitsu']['TotalProgressPercent']

        if state == "Completed":
            print("BIOS Restore has been completed successfully.")
            break
        else:
            print("Progress: {}%".format(progress))
        # check the task status every 10 seconds
        time.sleep(10)

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
        help="BIOS configuration file name"
    )

    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    bios_config = args.file

    restore_bios_config(irmc, user, password, bios_config)


if __name__ == '__main__':
    main()
