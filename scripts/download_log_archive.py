#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to download a log archive via iRMC Redfish API
  in Fujitsu PRIMERGY

  [Usage]
  - Download a log archive
  $ python download_log_archive.py -i 192.168.10.10 -u admin -p admin -f archive.zip

"""
import sys
import time
import argparse
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.2"


def download_log_archive(irmc, user, password, archive_name):
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

    response = session.get('https://{}/redfish/v1/Managers/iRMC'.format(irmc))
    irmc_fw = response.json()['FirmwareVersion']
    irmc_model = response.json()['Model']

    if irmc_model == 'iRMC S4' and int(irmc_fw[0:-1].replace('.','')) < 960:
        print("ERROR: The Log Archive endpoint is not supported in {} firmware {}.".format(irmc_model, irmc_fw))
        sys.exit()

    # Generate a log file archive
    url = "https://{}/redfish/v1/Oem/ts_fujitsu/FileDownload/Actions/FTSFileDownload.GenerateLogFileArchive".format(irmc)
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
            print("Generating a log file archive. Please wait...", end='\r')
        
        # check the task status every second
        time.sleep(1)
        max_wait_time -= 1

    if max_wait_time == 0:
        print("\nERROR: Generating a log archive did not complete in time. Please check the task log at {}/Oem/ts_fujitsu/Logs".format(task_url))
    else:
        # Download the archive from iRMC
        url = "https://{}/redfish/v1/Oem/ts_fujitsu/FileDownload/Actions/FTSFileDownload.DownloadLogFileArchive".format(irmc)
        response = session.post(url)
        status_code = response.status_code

        if status_code != 200:
            print("ERROR: Failed to download a log archive from iRMC. (error: {})".format(response.json()['error']['message']))
        else:
            with open(archive_name, 'wb') as newfile:
                newfile.write(response.content)
                print("iRMC Log Archive has been saved to {} successfully.".format(archive_name))

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
        default="LogArchive.zip",
        help="iRMC log archive file name")

    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    archive_name = args.file

    download_log_archive(irmc, user, password, archive_name)


if __name__ == '__main__':
    main()
