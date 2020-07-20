#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to reboot iRMC via iRMC Redfish API
  in Fujitsu PRIMERGY
"""

import sys
import argparse
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"


def reboot_irmc(irmc, user, password):
    url = "https://{}/redfish/v1/Managers/iRMC/Actions/Manager.Reset".format(
        irmc)

    response = requests.post(url, auth=(user, password), verify=False)

    if response.status_code != 204:
        print("ERROR: The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        sys.exit()

    print("The request has been sent to iRMC successfully.")


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

    reboot_irmc(irmc, user, password)


if __name__ == '__main__':
    main()
