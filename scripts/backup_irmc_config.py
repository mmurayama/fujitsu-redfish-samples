#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to back up all iRMC settings via iRMC Redfish API
  in Fujitsu PRIMERGY

  [Usage]
  - Show iRMC settings on console
  $ python backup_irmc_config.py -i 192.168.10.10 -u admin -p admin

  - Save iRMC settings to a file
  $ python backup_irmc_config.py -i 192.168.10.10 -u admin -p admin -f irmc.pre

"""
import sys
import argparse
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"


def backup_irmc_config(irmc, user, password, filename):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/xml, application/json'
    }
    url = "https://{}/redfish/v1/Managers/iRMC/Actions/Oem/FTSManager.SaveFullConfiguration".format(
        irmc)

    response = requests.post(
        url,
        headers=headers,
        auth=(user, password),
        verify=False
    )

    if response.status_code != 200:
        print("ERROR: The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        sys.exit()

    if filename is not None:
        with open(filename, 'w') as newfile:
            newfile.write(response.text)
        print("The iRMC configuraiton has been saved to {} successfully.".format(filename))
    else:
        print(response.text)


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
        help="iRMC backup file name. If not specified, print the config on stdout."
    )

    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    filename = args.file

    backup_irmc_config(irmc, user, password, filename)


if __name__ == '__main__':
    main()
