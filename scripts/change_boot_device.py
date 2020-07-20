#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to change boot device via iRMC Redfish API
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


def change_boot_device(irmc, user, password, bootdevice, nextbootonly):
    url = "https://{}/redfish/v1/Systems/0/Oem/ts_fujitsu/BootConfig".format(
        irmc)
    bootdevice_list = ['Pxe', 'Floppy', 'Cd', 'Hdd', 'BiosSetup']

    response = requests.get(url, auth=(user, password), verify=False)
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        sys.exit()

    current_bootdevice = response.json()['BootDevice']
    etag = response.json()['@odata.etag']

    if bootdevice == current_bootdevice:
        print("The boot device is already set to the requested device: {}".format(
            current_bootdevice))
        sys.exit()

    if bootdevice not in bootdevice_list:
        print("The boot device must be either Pxe, Floppy, Cd, Hdd, or BiosSetup.")
        sys.exit()

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        "If-Match": etag
    }
    payload = {
        'BootDevice': bootdevice,
        'NextBootOnlyEnabled': nextbootonly.lower()
    }
    response = requests.patch(url, headers=headers, auth=(
        user, password), data=json.dumps(payload), verify=False)
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        sys.exit()

    print("The boot device has been changed to {} successfully.".format(bootdevice))


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
        '-b', '--bootdevice',
        required=True,
        help="Boot Device: Pxe, Floppy, Cd, Hdd, or BiosSetup")
    parser.add_argument(
        '-n', '--nextbootonly',
        default=True,
        help="Change effects next boot only or permanent: True or False")

    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    bootdevice = args.bootdevice
    nextbootonly = args.nextbootonly

    change_boot_device(irmc, user, password, bootdevice, nextbootonly)


if __name__ == '__main__':
    main()
