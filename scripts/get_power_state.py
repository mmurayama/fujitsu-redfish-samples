#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to get system power state via iRMC Redfish API
  in Fujitsu PRIMERGY
"""
import sys
import argparse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"


def get_system_power_state(irmc, user, password):
    url = "https://{}/redfish/v1/Systems/0/".format(irmc)

    response = requests.get(url, auth=(user, password), verify=False)
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        sys.exit()

    print("System Power State is {}".format(response.json()['PowerState']))


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

    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password

    get_system_power_state(irmc, user, password)


if __name__ == '__main__':
    main()
