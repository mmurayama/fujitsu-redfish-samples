#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to get SEL entries via Redfish REST API
  in Fujitsu PRIMERGY

  [Usage]
  - Show all events
  $ python get_sel.py -i 192.168.10.10 -u admin -p admin

  - Show the specified event only
  $ python get_sel.py -i 192.168.10.10 -u admin -p admin -e 118
"""
import sys
import argparse
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"


def get_sel(irmc, user, password, event_id):
    session = requests.Session()
    session.verify = False

    header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    payload = {'UserName': user, 'Password': password}
    sessions_url = "https://{}/redfish/v1/SessionService/Sessions".format(irmc)

    response = session.post(sessions_url,
                            headers=header,
                            data=json.dumps(payload))

    if response.status_code != 201:
        print("ERROR: Failed to create a session.")
        print("DETAILS: {}".format(response.json()['error']['message']))
        sys.exit()

    session.headers.update({"X-Auth-Token": response.headers["X-Auth-Token"]})
    session_info = response.headers["Location"]

    response = session.get("https://{}/redfish/v1/Managers/iRMC/LogServices/SystemEventLog/Entries".format(irmc))

    if response.status_code != 200:
        print("ERROR: Failed to get the system event log information from the iRMC at {}".format(irmc))
        print("DETAILS: {}".format(response.json()['error']['message']))
        session.delete("https://{}{}".format(irmc, session_info))
        sys.exit()

    sel_entries_list = response.json()['Members']

    if event_id is None:
        print("ID".rjust(3) + " | " + "Data/Time".ljust(25) +
              " | " + "Severity".ljust(8) + " | Event")
        print("------------------------------------------------------------------")
        for entry in sel_entries_list:
            print(entry["Id"].rjust(3) + " | " + entry["Created"].rjust(25) +
                  " | " + entry['Severity'].ljust(8) + " | " + entry["Message"])
    else:
        found = False
        for entry in sel_entries_list:
            if int(entry['Id']) == event_id:
                print("ID".rjust(3) + " | " + "Data/Time".ljust(25) +
                      " | " + "Severity".ljust(8) + " | Event")
                print("------------------------------------------------------------------")
                print(entry["Id"].rjust(3) + " | " + entry["Created"].rjust(25) +
                      " | " + entry['Severity'].ljust(8) + " | " + entry["Message"])
                found = True
                break

        if found == False:
            print("ERROR: Could not find the specified event (ID: {})".format(event_id))

    session.delete("https://{}{}".format(irmc, session_info))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--irmc',
                        required=True,
                        help="iRMC IP address/hostname/FQDN")
    parser.add_argument('-u', '--user',
                        default="admin",
                        help="iRMC user name")
    parser.add_argument('-p', '--password',
                        default="admin",
                        help="iRMC password")
    parser.add_argument('-e', '--event',
                        type=int,
                        help="Show the event specified by the ID")
    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    event_id = args.event

    get_sel(irmc, user, password, event_id)

    return 0


if __name__ == '__main__':
    main()
