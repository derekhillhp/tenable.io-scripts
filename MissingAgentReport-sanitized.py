#Created by DJ Wiza and Derek Hill
#
#The purose of this script is to determine which instances inside of AWS do not have Nessus agents installed
#on them. It will retrieve all the instances from AWS (using our internally developed tool) as well as all
#known agents inside of Tenable.io and mark them as either having an agent or not. The output is in a CSV file.

import json
import csv
import os
import requests
import time
import datetime
import multiprocessing


# Python does not use the system proxy settings in Windows, and instead looks for the HTTPS_PROXY environment variable.
os.environ['HTTPS_PROXY'] = '<insert your proxy server here, if needed>' #comment out if no proxy is needed
ACCESS_KEY = "<insert your own key here>"
SECRET_KEY = "<insert your own key here>"
NESSUS_BASE_URL = "https://cloud.tenable.com"
OUTPUT_FOLDER = "C:/Temp/nessus/"

HEADERS = {'X-ApiKeys': 'accessKey=' + ACCESS_KEY + '; secretKey=' + SECRET_KEY}

#Zeus is our internal tool that collects all the information from Amazon such as host information, etc
#This part of the code will not work, but you can use this to see how data can be matched, possibly using
#a tool like security monkey
def GetHostsFromZeus():
    # Get all the hosts from Zeus
    result = requests.get('<some URL>')
    hosts = json.loads(result.text)

    # Filter out hosts that are not Linux or Windows and are not Terminated
    allHosts = []
    for host in hosts.values():
        if host['status'] == 'terminated' or host['platform'] not in ['windows', 'linux']:
            continue
        allHosts.append(host)

    return allHosts


def GetAssetList():
    response = requests.get(NESSUS_BASE_URL + '/workbenches/assets?date_range=90', headers=HEADERS)
    assets = json.loads(response.text)
    return assets['assets']


def GetAssetDetailsProcess(asset):
    response = requests.get(NESSUS_BASE_URL + '/workbenches/assets/' + asset['id'] + '/info', headers=HEADERS)
    details = json.loads(response.text)
    if 'info' not in details:
        print(asset['id'], 'did not return details["info"]')
        print(asset)
        return None

    if 'aws_ec2_instance_id' in details['info'] and details['info']['aws_ec2_instance_id']:
        return details['info']

    return None


def GetAssetDetails(assets):
    assetDetails = []
    begin = time.time()
    pool = multiprocessing.Pool(8)
    iter = pool.imap(GetAssetDetailsProcess, assets)
    i = 0
    while True:
        i += 1
        try:
            result = iter.next()
        except StopIteration:
            break
        if result is None:
            continue
        assetDetails.append(result)
        if i % 5 == 0:
            perSecond = i / (time.time() - begin)
            remaining = int((len(assets) - i) / perSecond)
            minutesRemaining = int(remaining / 60)
            secondsRemaining = remaining % 60
            print(i, '/', len(assets), ', ETC: ', minutesRemaining, ' minutes, ', secondsRemaining, ' seconds', sep='')

    return assetDetails


def MarkAgentPresence(hosts, assetDetails):
    numWithAgents = 0
    numWithoutAgents = 0
    instancesWithAgents = [asset['aws_ec2_instance_id'][0] for asset in assetDetails]
    for host in hosts:
        if host['id'] in instancesWithAgents:
            host['Has Agent'] = 'TRUE'
            numWithAgents += 1
        else:
            host['Has Agent'] = 'FALSE'
            numWithoutAgents += 1

    return numWithAgents, numWithoutAgents


def main():
    if not os.path.isdir(OUTPUT_FOLDER):
        print('Output folder', OUTPUT_FOLDER, 'does not exist.  Please create this folder.')
        return

    path = OUTPUT_FOLDER + 'AWS-without-nessus-agents-' + datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d') + '.csv'
    print('File will be saved to', path)

    try:
        fileOut = open(path, 'w')
    except PermissionError:
        print('Could not open output file for writing.  Is the file already open in another process?')
        return

    print('Fetching host list from Zeus')
    hosts = GetHostsFromZeus()
    print('Found', len(hosts), 'hosts')

    print('Fetching asset list from Nessus')
    assets = GetAssetList()
    print('Found', len(assets), 'assets.')

    print('Fetching asset details')
    begin = time.time()
    assetDetails = GetAssetDetails(assets)
    print('Found details for', len(assetDetails), 'assets')
    timeTaken = int(time.time() - begin)
    print('Details acquired in', timeTaken // 60, 'minutes and', timeTaken % 60, 'seconds')

    print('Finding hosts missing agents')
    numWithAgents, numWithoutAgents = MarkAgentPresence(hosts, assetDetails)

    # Translate from keys into field names
    fields = ['Instance ID', 'Has Agent', 'Instance Name', 'IP Address', 'AWS Region', 'Availability Zone', 'Project',
              'Age', 'Status', 'Platform', 'Creator', 'VPC ID', 'VPC Name', 'Service name']
    finalList = []
    for host in hosts:
        finalList.append({
            'Instance ID': host['id'],
            'Has Agent': host['Has Agent'],
            'Instance Name': host['name'],
            'IP Address': host['ip'],
            'AWS Region': host['region'],
            'Availability Zone': host['az'],
            'Project': host['project'],
            'Age': host['age'],
            'Status': host['status'],
            'Platform': host['platform'],
            'Creator': host['creator'],
            'VPC ID': host['vpc-id'],
            'VPC Name': host['vpc-name'],
            'Service name': host['service']
        })

    print('Sorting data')
    finalList.sort(key=lambda host: host['Instance ID'])
    finalList.sort(key=lambda host: host['Has Agent'])
    finalList.sort(key=lambda host: host['Project'])

    print('Writing to', path)
    mycsv = csv.DictWriter(fileOut, lineterminator='\n', fieldnames=fields, quoting=csv.QUOTE_MINIMAL)
    mycsv.writeheader()
    for row in finalList:
        mycsv.writerow(row)

    # Create fake data items at the end to create summary
    # Blank row
    d = {key: '' for key in fields}
    mycsv.writerow(d)

    d['Instance ID'] = 'Total Systems'
    d['Has Agent'] = len(finalList)
    mycsv.writerow(d)

    d['Instance ID'] = 'Systems without agents'
    d['Has Agent'] = numWithoutAgents
    mycsv.writerow(d)

    percentWithoutAgents = '%.2f%%' % ((numWithoutAgents / len(finalList) * 100))
    d['Instance ID'] = '% of systems without agents'
    d['Has Agent'] = percentWithoutAgents
    mycsv.writerow(d)

    fileOut.close()
    print('Done.')

    print('Total Systems:', len(finalList))
    print('Systems without agents:', numWithoutAgents)
    print('Percent without agents:', percentWithoutAgents)

if __name__ == '__main__':
    main()