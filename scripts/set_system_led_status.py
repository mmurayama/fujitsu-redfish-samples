#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to set System ID LED status via iRMC Redfish API
  in Fujitsu PRIMERGY
"""

import sys
import argparse
import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"


def set_system_led_status(irmc, user, password, led):
    url = "https://{}/redfish/v1/Systems/0/".format(irmc)

    response = requests.get(url, auth=(user, password), verify=False)
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        sys.exit()

    current_state = response.json()['IndicatorLED']
    etag = response.json()['@odata.etag']
    led_status_list = response.json()['IndicatorLED@Redfish.AllowableValues']

    if led == current_state:
        print("The system indicator LED state is the same as the requested state: {}".format(led))
        sys.exit()

    if led not in led_status_list:
        print("The LED state must be Lit, Off, or Blinking.")
        sys.exit()

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        "If-Match": etag
    }
    payload = {'IndicatorLED': led}
    response = requests.patch(url, headers=headers, auth=(
        user, password), data=json.dumps(payload), verify=False)
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        sys.exit()

    print("The System indicator LED state has been changed to {} successfully.".format(led))


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
        '-l', '--led',
        required=True,
        help="System Indicator LED Status: Off, Blinking, or Lit")

    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    led = args.led

    set_system_led_status(irmc, user, password, led)


if __name__ == '__main__':
    main()
