#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to update iRMC Firmware via iRMC Redfish API
  in Fujitsu PRIMERGY

  [Usage]
  $ python ./update_irmc_firmware.py -i 192.168.10.10 -u admin -p admin -f ./RX2530M4_0263Psdr0352.bin
"""
import os.path
import sys
import time
import argparse
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama <mmurayama@fujitsu.com>"
__version__ = "0.0.1"


def update_irmc_firmware(irmc, user, password, irmcfile):
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
    session_info = response.headers["Location"]

    systems_response = session.get(
        "https://{}/redfish/v1/Systems/0".format(irmc))
    power_state = systems_response.json()['PowerState']

    irmc_update_url = "https://{}/redfish/v1/Managers/iRMC/Actions/Oem/FTSManager.FWUpdate".format(
        irmc)
    payload = {'data': open(irmcfile, 'rb')}
    response = session.post(
        irmc_update_url,
        files=payload
    )
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("ERROR: The iRMC Update POST request failed (url: {0}, error: {1})".format(
            irmc_update_url, response.json()['error']['message']))
        sys.exit()

    task_url = "https://{0}{1}".format(irmc, response.headers['Location'])
    while True:
        try:
            response = session.get(task_url)
            response_data = response.json()
            state = response_data['TaskState']
            progress = response_data['Oem']['ts_fujitsu']['TotalProgressPercent']

            if state == "Completed":
                if power_state == "On":
                    print("iRMC Update has been completed successfully. Please reboot the iRMC.")
                else:
                    print("iRMC Update has been completed successfully.")
                break
            else:
                print("Progress: {}%".format(progress))
            # check the task status every 10 seconds
            time.sleep(10)
        except Exception as e:
            # If the system is powered off and the current FW is the same as the update file or iRMC Update is completed,
            # iRMC will reboot, so the connection will be disconnected, and that generate an exception.
            if progress == 100:
                print("iRMC Update has been completed successfully, and iRMC will reboot automatically.")
            else:
                print("ERROR: An exception is thrown. Check the network connection to iRMC, or the iRMC status as iRMC may be being rebooted.")
                print("Exception: {}".format(e))
            sys.exit()

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
        required=True,
        help="iRMC Update File (.bin)"
    )
    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    irmcfile = args.file

    if not os.path.isfile(irmcfile):
        print("ERROR: Cannot find the speficied iRMC update file.")
        sys.exit()

    update_irmc_firmware(irmc, user, password, irmcfile)


if __name__ == '__main__':
    main()
