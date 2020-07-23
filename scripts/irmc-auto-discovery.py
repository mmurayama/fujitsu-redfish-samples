#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
 Sample script to search/configure iRMC on the network via SSDP and Redfish

 Copyright (C) 2020 Masahiro Murayama

 [Usage]
 - List discovered system on the network
 $ python ./irmc-auto-discovery.py show

 - Set the IPv4 address/netmask/gateway to the target iRMC
 $ python ./irmc-auto-discovery.py configure -s <serial number> -i <ip address> -m <netmask> -g <gateway>

'''

import sys
import socket
import argparse
import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def discover_irmc():
    message = \
        'M-SEARCH * HTTP/1.1\r\n' \
        'HOST:[ff02::c]:1900\r\n' \
        'ST: urn:dmtf-org:service:redfish-rest:1\r\n' \
        'MX:3\r\n' \
        'MAN:"ssdp:discover"\r\n' \
        '\r\n'

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(4)
    s.sendto(bytes(message, 'UTF-8'), ('ff02::c', 1900))

    url_set = set()
    try:
        while True:
            data, addr = s.recvfrom(65507)
            # print(data)
            # print(addr)
            url_set.add('https://[{}]/redfish/v1/'.format(addr[0]))
    except socket.timeout:
        pass

    return url_set


def show_info(url_set, user, password):
    for url in url_set:
        try:
            headers = {'Accept': 'application/json',
                       'Content-Type': 'application/json'}
            response = requests.get(url, headers=headers, verify=False)
            model = response.json()['Oem']['ts_fujitsu']['AutoDiscoveryDescription']['ServerNodeInformation']['Model']
            sn = response.json()['Oem']['ts_fujitsu']['AutoDiscoveryDescription']['ServerNodeInformation']['SerialNumber']

            response = requests.get(url + "Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Lan",
                                    headers=headers, auth=(user, password), verify=False)
            ipv4_addr = response.json()['IpV4']['IpAddress']
            ipv4_dhcp = response.json()['IpV4']['UseDhcp']

            print("Model: {0}, S/N: {1}, IPv4: {2}".format(model, sn, ipv4_addr))
        except Exception as e:
            print(e)


def configure_irmc(user, password, serial, address, netmask, gateway):
    urls = discover_irmc()

    for url in urls:
        try:
            headers = {'Accept': 'application/json',
                       'Content-Type': 'application/json'}
            response = requests.get(url, headers=headers, verify=False)
            if response.json()['Oem']['ts_fujitsu']['AutoDiscoveryDescription']['ServerNodeInformation']['SerialNumber'] == serial:
                response = requests.get(url + "Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Lan",
                                        headers=headers, auth=(user, password), verify=False)
                etag = response.json()['@odata.etag']
                headers = {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'If-Match': etag
                }
                payload = {
                    'IpV4': {
                        'UseDhcp': 'false',
                        'IpAddress': address,
                        'SubnetMask': netmask,
                        'DefaultGateway': gateway,
                    }
                }
                response = requests.patch(url + "Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Lan",
                                          headers=headers, auth=(user, password), data=json.dumps(payload), verify=False)
                if response.status_code == 200:
                    print("The iRMC network has been configured successfully. Please wait for a few minutes for iRMC to activate the new configuration.")
                else:
                    print("The request failed (error: {0})".format(response.json()['error']['message']))

                break
        except Exception as e:
            print(e)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'action',
        choices=['show', 'configure'],
        help="show or configure. if configure is specified, Must use with -a, -m, and -g.")
    parser.add_argument(
        '-u', '--user',
        default="admin",
        help="iRMC user name")
    parser.add_argument(
        '-p', '--password',
        default="admin",
        help="iRMC password")
    parser.add_argument(
        '-a', '--address',
        help="IPv4 address")
    parser.add_argument(
        '-m', '--netmask',
        help="Netmask")
    parser.add_argument(
        '-g', '--gateway',
        help="Gateway")
    parser.add_argument(
        '-s', '--serial',
        help="System serial number")

    args = parser.parse_args()
    user = args.user
    password = args.password

    if args.action == 'show':
        show_info(discover_irmc(), user, password)
    elif args.action == 'configure':
        address = args.address
        netmask = args.netmask
        gateway = args.gateway
        serial = args.serial

        if address is not None and netmask is not None and gateway is not None and serial is not None:
            configure_irmc(user, password, serial, address, netmask, gateway)
        else:
            print("ERROR: '-a', '-m', '-g', and '-s' must be specified.")
            sys.exit()


if __name__ == '__main__':
    main()
