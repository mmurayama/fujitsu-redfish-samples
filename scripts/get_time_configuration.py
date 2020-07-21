#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to get the Time configurations via iRMC Redfish API
  in Fujitsu PRIMERGY

  [Usage]
  $ python ./get_time_configuration -i 192.168.10.10 -u admin -p admin
"""
import sys
import argparse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"


def get_time_config(irmc, user, password):
    url = "https://{}/redfish/v1/Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Time/".format(
        irmc)
    response = requests.get(url, auth=(user, password), verify=False)
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        sys.exit()

    if response.json()['SyncSource'] == 'NTP':
        print("Time Mode: NTP")
        print("Time Zone: {}".format(response.json()['TimeZone']))

        response = requests.get(
            "https://{}/redfish/v1/Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Time/NtpServers".format(
                irmc),
            auth=(user, password),
            verify=False
        )
        count = response.json()['Members@odata.count']
        i = 0
        while i < count:
            response = requests.get(
                "https://{}/redfish/v1/Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Time/NtpServers/{}".format(
                    irmc, i),
                auth=(user, password),
                verify=False
            )
            print("NTP Server[{}]: {}".format(
                i, response.json()['NtpServerName']))
            i += 1
    else:
        print("Time Mode: System RTC")
        print("Time Zone: {}".format(response.json()['TimeZone']))
        print("RTC Mode: {}".format(response.json()['RtcMode']))


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

    get_time_config(irmc, user, password)


if __name__ == '__main__':
    main()
