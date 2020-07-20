#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to update BIOS remotely via iRMC Redfish API
  in Fujitsu PRIMERGY
"""
import os.path
import sys
import time
import argparse
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"


def update_bios(irmc, user, password, biosfile):
    # First, create a session to iRMC
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
        print("ERROR: Could not establish a session to the iRMC")
        sys.exit()
    session.headers.update({"X-Auth-Token": response.headers["X-Auth-Token"]})
    session_info = response.headers['Location']

    # Second, check the current power status
    response = session.get('https://%s/redfish/v1/Systems/0/' % irmc)
    current_power_state = response.json()['PowerState']

    # Then, send an update request to iRMC
    bios_update_url = "https://{}/redfish/v1/Systems/0/Bios/Actions/Oem/FTSBios.BiosUpdate".format(
        irmc)
    payload = {'data': open(biosfile, 'rb')}
    response = session.post(
        bios_update_url,
        files=payload
    )
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The BIOS Update POST request failed (url: {0}, error: {1})".format(
            bios_update_url, response.json()['error']['message']))
        sys.exit()

    # If the system is on, just stage the BIOS file, so a reboot is required later to apply the BIOS update.
    # If the system is off, then continue to monitor the update progress until it's done.
    if current_power_state == 'On':
        print("The BIOS update file has been uploaded to iRMC successfully. Please reboot your system to apply the update.")
        session.delete("https://{0}{1}".format(irmc, session_info))
        # if response.status_code == 200:
        #    print("Session has been deleted successfully.")
        # else:
        #    print("Session could not be deleted properly.")
        sys.exit()

    task_url = "https://{0}{1}".format(irmc, response.headers['Location'])

    while True:
        response = session.get(task_url)
        response_data = response.json()
        state = response_data['TaskState']
        progress = response_data['Oem']['ts_fujitsu']['TotalProgressPercent']

        if state == "Completed":
            print("BIOS Update has been completed successfully.")
            break
        else:
            print("Progress: {}%".format(progress))
        # check the task status every 10 seconds
        time.sleep(10)

    session.delete("https://{0}{1}".format(irmc, session_info))
    # if response.status_code == 200:
    #    print("Session has been deleted successfully.")
    # else:
    #    print("Session could not be deleted properly.")


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
        required=True,
        help="BIOS Update File (.UPC)"
    )
    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    biosfile = args.file

    if not os.path.isfile(biosfile):
        print("ERROR: Cannot find the speficied BIOS update file at {}.".format(biosfile))
        sys.exit()

    update_bios(irmc, user, password, biosfile)


if __name__ == '__main__':
    main()
