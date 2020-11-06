#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to take an iRMC console screenshot via iRMC Redfish API
  in Fujitsu PRIMERGY

  [Usage]
  - Take a screenshot and save it to screenshot.jpg
  $ python take_console_screenshot.py -i 192.168.10.10 -u admin -p admin -f screenshot.jpg

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


def take_console_screenshot(irmc, user, password, filename):
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

    # Before sending a "take a screenshot" request, check the power status.
    # If the target is powered off, no need to take a screenshot.
    url = "https://{}/redfish/v1/Systems/0".format(irmc)
    response = session.get(url)
    
    if response.status_code != 200:
        print("ERROR: Failed to get the current power status (url: {}, status_code: {}, error: {}".format(url, response.status_code, response.text))
        session.delete("https://{0}{1}".format(irmc, session_info))
        sys.exit()
    else:
        if response.json()['PowerState'] != 'On':
            print("ERROR: The system is not powered on.")
            session.delete("https://{0}{1}".format(irmc, session_info))
            sys.exit()

    # Take a screenshot
    url = "https://{}/redfish/v1/Systems/0/Actions/Oem/FTSComputerSystem.Screenshot".format(irmc)
    payload = {"FTSScreenshotType":"Make"}
    response = session.post(url, headers=headers, data=json.dumps(payload))
    status_code = response.status_code

    if status_code != 204:
        print("ERROR: The request failed (url: {0}, status_code: {1}, error: {2})".format(
           url, status_code, response.text))
        session.delete("https://{0}{1}".format(irmc, session_info))
        sys.exit()

    # Download the screenshot from iRMC
    action_info_url = "https://{}/redfish/v1/Systems/0/Oem/ts_fujitsu/FTSComputerSystemScreenshotActionInfo".format(irmc)
    response = session.get(action_info_url)
    allowable_values = response.json()['Parameters'][0]['AllowableValues']

    if 'Save' not in allowable_values:
        print("ERROR: Downloading a screnshot is not allowed currently. Check the iRMC status.")
        session.delete("https://{0}{1}".format(irmc, session_info))
        sys.exit()

    payload = {"FTSScreenshotType":"Save"}
    response = session.post(url, headers=headers, data=json.dumps(payload))
    status_code = response.status_code

    if status_code != 200:
        print("ERROR: Failed to download the screenshot from iRMC. (error: {})".format(response.text))
    else:
        with open(filename, 'wb') as newfile:
            newfile.write(response.content)
            print("Screenshot has been saved to {} successfully.".format(filename))

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
        default="screenshot.jpg",
        help="screenshot file name")

    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    filename = args.file

    take_console_screenshot(irmc, user, password, filename)


if __name__ == '__main__':
    main()
