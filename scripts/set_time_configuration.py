#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Sample script to set the Time configuration via iRMC Redfish API
  in Fujitsu PRIMERGY

  [Usage]
  - Set the time mode to iRMC, the RTC mode to UTC, and the time zone to 'US/Pacific'
  $ python ./set_time_configuraiton -i 192.168.10.10 -m iRMC -rtc UTC -tz US/Pacific

  - Set the time mode to NTP, and '8.8.8.8' and '10.10.10.10' as NTP servers.
  $ python ./set_time_configuration -i 192.168.10.10 -m NTP -n 8.8.8.8,10.10.10.10
"""
import sys
import argparse
import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = "Masahiro Murayama"
__version__ = "0.0.1"


def set_time_configuration(irmc, user, password, timemode, rtcmode, timezone, ntpserver_list):
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

    url = "https://{}/redfish/v1/Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Time".format(
        irmc)
    response = session.get(url)
    status_code = response.status_code

    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        session.delete("https://{0}{1}".format(irmc, session_info))
        sys.exit()

    etag = response.json()['@odata.etag']

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        "If-Match": etag
    }

    payload = {'SyncSource': timemode}

    if rtcmode is not None:
        payload['RtcMode'] = rtcmode

    if timezone is not None:
        payload['TimeZone'] = timezone

    response = session.patch(url, headers=headers, data=json.dumps(payload))
    status_code = response.status_code
    if status_code != 200 and status_code != 202 and status_code != 204:
        print("The request failed (url: {0}, error: {1})".format(
            url, response.json()['error']['message']))
        session.delete("https://{0}{1}".format(irmc, session_info))
        sys.exit()

    if len(ntpserver_list) > 0:
        i = 0
        while i < 2:
            url = "https://{}/redfish/v1/Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Time/NtpServers/{}".format(
                irmc, i)
            response = session.get(url)
            if status_code != 200 and status_code != 202 and status_code != 204:
                print("The request failed (url: {0}, error: {1})".format(
                    url, response.json()['error']['message']))
                session.delete("https://{0}{1}".format(irmc, session_info))
                sys.exit()
            etag = response.json()['@odata.etag']
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                "If-Match": etag
            }
            session.patch(url, headers=headers, data=json.dumps(
                {"NtpServerName": ntpserver_list[i]}))
            i += 1

    session.delete("https://{0}{1}".format(irmc, session_info))
    print("Time configuration has been updated successfully.")


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
        '-m', '--timemode',
        required=True,
        choices=['iRMC', 'NTP'],
        help="Time Mode: iRMC or NTP")
    parser.add_argument(
        '-rtc', '--rtcmode',
        choices=['LocalTime', 'UTC'],
        help="RTC Mode: LocalTime or UTC")
    parser.add_argument(
        '-tz', '--timezone',
        help="Time Zone")
    parser.add_argument(
        '-n', '--ntpserver',
        help="NTP servers. Comma separated."
    )

    args = parser.parse_args()
    irmc = args.irmc
    user = args.user
    password = args.password
    timemode = args.timemode
    rtcmode = args.rtcmode
    timezone = args.timezone
    ntpserver = args.ntpserver
    ntpserver_list = list()

    if ntpserver is not None:
        if ',' in ntpserver:
            ntpserver_list = ntpserver.split(',')
        else:
            ntpserver_list.append(ntpserver)

    # if len(ntpserver_list) > 2:
    #    print("ERROR: The number of NTP servers you can set is up to 2.")
    #    sys.exit()
    set_time_configuration(irmc, user, password, timemode,
                           rtcmode, timezone, ntpserver_list)


if __name__ == '__main__':
    main()
