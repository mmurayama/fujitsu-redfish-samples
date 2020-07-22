#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to get System Firmware information via iRMC Redfish API
  in Fujitsu PRIMERGY

  [Usage]
  $ python ./get_system_firmware_info.py -i 192.168.10.10 -u admin -p admin
"""
import sys
import argparse
import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"


def check_nic_fw(session, url):
    response = session.get(url + '/NIC')
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        return

    nic_list = response.json()['Ports']

    if len(nic_list) == 0:
        return

    for nic in nic_list:
        if 'FirmwareVersion' in nic:
            if 'AdapterName' in nic:
                print("{} FW in Slot {} Port {}: {}".format(
                    nic['AdapterName'], nic['SlotId'], nic['PortId'], nic['FirmwareVersion']))
            else:
                print("{} FW in Slot {} Port {}: {}".format(
                    nic['ModuleName'], nic['SlotId'], nic['PortId'], nic['FirmwareVersion']))


def check_fc_fw(session, url):
    response = session.get(url + '/FC')
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        return

    fc_list = response.json()['Ports']

    if len(fc_list) == 0:
        return

    for fc in fc_list:
        if 'FirmwareVersion' in fc:
            if 'AdapterName' in fc:
                print("{} FW in Slot {} Port {}: {}".format(
                    fc['AdapterName'], fc['SlotId'], fc['PortId'], fc['FirmwareVersion']))
            else:
                print("{} FW in Slot {} Port {}: {}".format(
                    fc['ModuleName'], fc['SlotId'], fc['PortId'], fc['FirmwareVersion']))


def check_storage_fw(session, url):
    response = session.get(url + '/Storage')
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        return

    storage_list = response.json()['Adapters']

    if len(storage_list) == 0:
        return

    for storage in storage_list:
        if storage['ModuleName'] == 'Multiple Devices' or storage['ModuleName'] == 'Advanced Host Controller Interface' or storage['ModuleName'] is None:
            continue
        if 'FirmwareVersion' in storage:
            if storage['ModuleName'] == 'PSAS CP400i':
                print("{} FW: {}".format(
                    storage['ModuleName'], storage['FirmwareVersion']))
            else:
                print("{} FW: {}".format(
                    storage['ModuleName'], storage['FWPackageVersion']))


def get_system_fw_info(irmc, user, password):
    session = requests.Session()
    session.verify = False
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json'}
    payload = {'UserName': user, 'Password': password}
    sessions_url = "https://{}/redfish/v1/SessionService/Sessions".format(irmc)
    response = session.post(
        sessions_url,
        headers=headers,
        auth=(user, password),
        data=json.dumps(payload)
    )
    if response.status_code != 201:
        print("ERROR: Could not establish a session to the iRMC")
        sys.exit()
    session.headers.update({"X-Auth-Token": response.headers["X-Auth-Token"]})
    session_info = response.headers["Location"]

    url = "https://{}/redfish/v1/Systems/0/Oem/ts_fujitsu/FirmwareInventory".format(
        irmc)
    response = session.get(url)
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        session.delete("https://{0}{1}".format(irmc, session_info))
        sys.exit()

    data = response.json()
    print("System BIOS: {}".format(data['SystemBIOS']))
    print("iRMC Firmware: {} {}".format(
        data['BMCFirmware'], data['SDRRVersion']))

    # Check NIC firmware
    check_nic_fw(session, url)
    # Check FC firmware
    check_fc_fw(session, url)
    # Check Storage firmware
    check_storage_fw(session, url)

    session.delete("https://{0}{1}".format(irmc, session_info))


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

    get_system_fw_info(irmc, user, password)


if __name__ == '__main__':
    main()
