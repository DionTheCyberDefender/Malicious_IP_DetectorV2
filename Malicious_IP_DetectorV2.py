#Malicious_IP_DetectorV2.py
#Malicious IP Detector V2

#Purpose: To receive the user's input of a valid IP address and search the outcome via the user's choice of AbuseIPDB or VirusTotal.
#This will search an IP's Malicious Score, attributes, etc.

import requests
import json

#1 Ask user for the IP in question and remove Whitespace from str
ip_in_question = input("What is the IP in question? ").strip()
allowed_chars = "123456789."

#Convert the string to a float using float() and verify IP is in valid format (xxx.xxx.xxx.xxx)
try:
    float(ip_in_question)
    #If conversion is correct, check for valid IP (check for 3 dots)
    if ip_in_question.count(".") == 3:
        print("Thanks for providing the IP: ", ip_in_question)
    else:
        print("Error: Invalid IP format. Please Try Again")
        print("Enter a valid IP (Example: xxx.xxx.xxx.xxx)")
except ValueError:
    print("Thanks for providing the IP: ", ip_in_question)
    
#User must choose which tool to search the inputted IP on
tool_in_question = input('Now which tool would you like to use for your investigation? (Please select either "1" for AbuseIPDB or "2" for VirusTotal) ').strip()

#Defining the api-endpoint options for Version 2 of the Malicious IP Detector.
abuseipdb_url = 'https://api.abuseipdb.com/api/v2/check'
virustotal_url = 'https://www.virustotal.com/api/v3/ip_addresses/{ip_in_question}'

#Define API URLs and Headers Based On User's Input
if tool_in_question == '1': 
    url = abuseipdb_url
    querystring = {
    'ipAddress': ip_in_question,
    'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': 'Your_AbuseIPDB_API_Key'
    }
    
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    decodedResponse = json.loads(response.text)
    print(json.dumps(decodedResponse, sort_keys=True, indent=4))
    
    
elif tool_in_question == '2': 
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_in_question}'
    headers = {
        'Accept': 'application/json',
        'X-Apikey': 'Your_VirusTotal_API_Key'
    }

else:
    print('Error: Invalid Selection. Please be sure to select either "1" or "2"')
    exit() 

response = requests.get(url=url, headers=headers)

print(response.text)

results = input('Please Review the above results; Press "Enter" when done: ')
print(results)

#Author: DionTheCyberDefender 
#DateOfCreation 5/25/2024
