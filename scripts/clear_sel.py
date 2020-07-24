#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to clear SEL via Redfish REST API
  in Fujitsu PRIMERGY

  [Usage]
  $ python clear_sel.py -i 192.168.10.10 -u admin -p admin

"""
import argparse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"


def clear_sel(irmc, user, password):
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    url = "https://{}/redfish/v1/Managers/iRMC/LogServices/SystemEventLog/Actions/LogService.ClearLog".format(irmc)
    response = requests.post(url, headers=headers, auth=(user, password), verify=False)

    if response.status_code != 204:
        print("ERROR: Failed to clear the system event log from the iRMC at {}".format(irmc))
        print("DETAILS: {}".format(response.json()['error']['message']))
    else:
        print("SEL has been cleared successfully.")


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
    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password

    clear_sel(irmc, user, password)


if __name__ == '__main__':
    main()
