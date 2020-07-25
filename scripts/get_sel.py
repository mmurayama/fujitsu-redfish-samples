#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to get SEL entries via Redfish REST API
  in Fujitsu PRIMERGY

  [Usage]
  - Show all events
  $ python get_sel.py -i 192.168.10.10 -u admin -p admin

  - Show all events (ascending)
  $ python get_sel.py -i 192.168.10.10 -u admin -p admin -r

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
__version__ = "0.0.2"


def get_sel(irmc, user, password, ascend, event_id):
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    response = requests.get(
        "https://{}/redfish/v1/Managers/iRMC/LogServices/SystemEventLog/Entries".format(irmc),
        headers=headers,
        auth=(user, password),
        verify=False
    )

    if response.status_code != 200:
        print("ERROR: Failed to get the system event log information from the iRMC at {}".format(irmc))
        print("DETAILS: {}".format(response.json()['error']['message']))
        sys.exit()

    sel_entries_list = response.json()['Members']

    if ascend == True:
        sel_entries_list.reverse()

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
    parser.add_argument('-r',
                        action='store_true',
                        help="Ascending the events")
    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    event_id = args.event
    ascend = args.r

    get_sel(irmc, user, password, ascend, event_id)


if __name__ == '__main__':
    main()
