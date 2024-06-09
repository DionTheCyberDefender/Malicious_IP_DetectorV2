#! /usr/bin/env python3

#Author: DionTheCyberDefender 
#DateOfCreation 5/25/2024
#Purpose: To receive the user's input of a valid IP address and search the outcome via the user's choice of AbuseIPDB or VirusTotal.
#This will search an IP's Malicious Score, attributes, etc.

import requests
import json
import ipaddress
import sys
import argparse

AbuseIPDB_API_Key = ''
abuseipdb_url = 'https://api.abuseipdb.com/api/v2/check'

VirusTotal_API_Key = ''
virustotal_url = 'https://www.virustotal.com/api/v3/ip_addresses'


def test_with_abuseIPDB(ip_in_question):
    url = abuseipdb_url
    querystring = {
    'ipAddress': ip_in_question,
    'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': AbuseIPDB_API_Key
    }

    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
    decodedResponse = json.loads(response.text)
    print(json.dumps(decodedResponse, sort_keys=True, indent=4))

def test_with_virusTotal(ip_in_question):
    url = f'{virustotal_url}/{ip_in_question}'
    headers = {
        'Accept': 'application/json',
        'X-Apikey': VirusTotal_API_Key
    }

    try:
        response = requests.get(url=url, headers=headers)
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
    print(response.text)
    results = input('Please Review the above results; Press "Enter" when done: ')
    print(results)

def main():
    
    #define some arguments with help function
    parser = argparse.ArgumentParser(
        description='test', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(dest="ip_in_question",help="what IP would you like to check today?")
    parser.add_argument('-t','--tool', choices=['a', 'b'], default='a',
                        help=('which tool would you like to check your ip against?\n'
                              ' a = AbuseIPDB (Default)\n'
                              ' b = VirusTotal')) # can be added to if/when needed

    args = parser.parse_args()

    ip_in_question = args.ip_in_question
    tool_in_question = args.tool
    
    try:
        # ipaddress can validate ip address natively
        ipaddress.ip_address(ip_in_question)
        print("Thanks for providing the IP: ", ip_in_question)
    except ValueError as e:
        print(e)
        sys.exit(1)

    if args.tool == 'a':
        test_with_abuseIPDB(ip_in_question)
    elif args.tool == 'b':
        test_with_virusTotal(ip_in_question)

if __name__ == '__main__':
    main()
