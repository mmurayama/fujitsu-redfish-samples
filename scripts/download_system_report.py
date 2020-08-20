#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to download a system report via iRMC Redfish API
  in Fujitsu PRIMERGY

  [Usage]
  - Show a system report on console
  $ python download_system_report.py -i 192.168.10.10 -u admin -p admin

  - Save a system report to a file
  $ python download_system_report.py -i 192.168.10.10 -u admin -p admin -f report.xml
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


def download_system_report(irmc, user, password, report_name):
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

    # Generate a system report
    url = "https://{}/redfish/v1/Systems/0/Actions/Oem/FTSComputerSystem.SystemReportGenerate".format(irmc)
    response = session.post(url)
    status_code = response.status_code

    if status_code != 202:
        print("ERROR: The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        sys.exit()

    task_url = "https://{0}{1}".format(irmc, response.headers['Location'])

    # Will wait for up to 120 seconds for the task to be completed
    max_wait_time = 120
    while max_wait_time:
        response = session.get(task_url)

        if response.json()['TaskState'] == "Completed":
            break
        else:
            print("Generating a system report. Please wait...", end='\r')
        
        # check the task status every second
        time.sleep(1)
        max_wait_time -= 1

    if max_wait_time == 0:
        print("\nERROR: Generating a report did not complete in time. Please check the task log at {}/Oem/ts_fujitsu/Logs".format(task_url))
    else:
        # Download the report from iRMC
        url = "https://{}/redfish/v1/Systems/0/Actions/Oem/FTSComputerSystem.SystemReportDownload".format(irmc)
        response = session.post(url)
        status_code = response.status_code

        if status_code != 200:
            print("ERROR: Failed to download a report from iRMC. (error: {})".format(response.json()['error']['message']))
        else:
            if report_name is not None:
                with open(report_name, 'w') as newfile:
                    newfile.write(response.text)
                    print("iRMC System Report has been saved to {} successfully.".format(report_name))
            else:
                print(response.text)

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
        help="iRMC System Report file name"
    )

    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    report_name = args.file

    download_system_report(irmc, user, password, report_name)


if __name__ == '__main__':
    main()
