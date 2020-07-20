#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to set system power state via iRMC Redfish API
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


def set_system_power_state(irmc, user, password, state):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    url = "https://{}/redfish/v1/Systems/0/".format(irmc)

    response = requests.get(url, headers=headers,
                            auth=(user, password), verify=False)
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        sys.exit()

    print("Current System Power State: {}".format(
        response.json()['PowerState']))
    if state not in response.json()['Actions']['Oem']['http://ts.fujitsu.com/redfish-schemas/v1/FTSSchema.v1_0_0#FTSComputerSystem.Reset']['FTSResetType@Redfish.AllowableValues']:
        print("ERROR: The requested operation, {}, is not allowed.".format(state))
        sys.exit()

    url = "https://{}/redfish/v1/Systems/0/Actions/Oem/FTSComputerSystem.Reset".format(
        irmc)
    payload = {'FTSResetType': state}
    response = requests.post(url, headers=headers, auth=(user, password),
                             data=json.dumps(payload), verify=False)

    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        sys.exit()

    print("The requested operation, {}, was executed successfully.".format(state))


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
        '-s', '--state',
        required=True,
        help="Power action: on, off, cycle, reset, nmi, power_button, graceful_shutdown, or graceful_restart")
    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    state = args.state

    power_state = {
        'on': 'PowerOn',
        'off': 'PowerOff',
        'cycle': 'PowerCycle',
        'reset': 'ImmediateReset',
        'nmi': 'PulseNmi',
        'power_button': 'PressPowerButton',
        'graceful_shutdown': 'GracefulPowerOff',
        'graceful_restart': 'GracefulReset'
    }

    if state.lower() not in power_state.keys():
        print("ERROR: Power State must be on, off, cycle, reset, nmi, power_button, graceful_shutdown, or graceful_restart.")
        sys.exit()

    set_system_power_state(irmc, user, password, power_state[state.lower()])


if __name__ == '__main__':
    main()
