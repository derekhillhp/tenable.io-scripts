#Created by DJ Wiza
#
#This script will retrieve all systems that have either Meltdown or Spectre vulnerabilities
#and also retrieve some information from our in-house AWS management tool (this part will not function)
#to help us determine who the customer is.

import csv
import datetime
import json
import multiprocessing
import os
import pprint
import requests
import time

os.environ['HTTPS_PROXY'] = '<insert your proxy server here>' #comment out if no proxy server is used
ACCESS_KEY = "<insert your keys here>"
SECRET_KEY = "<insert your keys here>"
NESSUS_BASE_URL = "https://cloud.tenable.com"
OUTPUT_FOLDER = "C:/Temp/nessus/"

HEADERS = {'X-ApiKeys': 'accessKey=' + ACCESS_KEY + '; secretKey=' + SECRET_KEY}

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

def GetSpeltdownPlugins():
    pluginIDs = []
    # Get all plugin ID's that contain the word "meltdown"
    url = 'https://cloud.tenable.com/workbenches/vulnerabilities?date_range=90&filter.0.quality=match&filter.0.filter=plugin.name&filter.0.value=meltdown&filter.search_type=and'
    req = requests.get(url, headers=HEADERS)
    data = req.json()
    for vuln in data['vulnerabilities']:
        print(vuln['plugin_id'], '-', vuln['plugin_name'])
        pluginIDs.append(vuln['plugin_id'])

    # Get all plugin ID's that contain the word "spectre"
    url = 'https://cloud.tenable.com/workbenches/vulnerabilities?date_range=90&filter.0.quality=match&filter.0.filter=plugin.name&filter.0.value=spectre&filter.search_type=and'
    req = requests.get(url, headers=HEADERS)
    data = req.json()
    for vuln in data['vulnerabilities']:
        print(vuln['plugin_id'], '-', vuln['plugin_name'])
        pluginIDs.append(vuln['plugin_id'])

    return pluginIDs

def GetAffectedAssets(pluginIDs):
    assets = []
    for pluginID in pluginIDs:
        url = 'https://cloud.tenable.com/workbenches/vulnerabilities/{}/outputs?date_range=2'.format(pluginID)
        req = requests.get(url, headers=HEADERS)
        data = req.json()
        for output in data['outputs']:
            for state in output['states']:
                for result in state['results']:
                    for asset in result['assets']:
                        assets.append(asset['id'])
    return list(set(assets))

def GetAssetDetailsProcess(asset):
    response = requests.get(NESSUS_BASE_URL + '/workbenches/assets/' + asset + '/info', headers=HEADERS)
    details = json.loads(response.text)
    try:
        if 'aws_ec2_instance_id' in details['info'] and details['info']['aws_ec2_instance_id']:
            details = details['info']

            # Find OS version
            try:
                response = requests.get('https://cloud.tenable.com/workbenches/assets/{}/vulnerabilities/11936/outputs?date_range=2'.format(asset), headers=HEADERS)
                data = json.loads(response.text)
                details['OS'] = data['outputs'][0]['plugin_output'].splitlines()[1][26:]
            except Exception as e:
                print("Couldn't find OS for asset", asset)
                details['OS'] = 'UNKNOWN'


            # Search for AWS metadata plugin (Linux)
            response = requests.get('https://cloud.tenable.com/workbenches/assets/{}/vulnerabilities/90191/outputs?date_range=2'.format(asset), headers=HEADERS)
            data = json.loads(response.text)
            details['hostname'] = ''
            try:
                details['hostname'] = data['outputs'][0]['states'][0]['results'][0]['assets'][0]['hostname']
            except Exception as e:
                # Couldn't find it?  Try looking for the Windows version of the AWS metadata plugin
                response = requests.get(
                    'https://cloud.tenable.com/workbenches/assets/{}/vulnerabilities/90427/outputs?date_range=2'.format(
                        asset), headers=HEADERS)
                data = json.loads(response.text)
                details['hostname'] = ''
                try:
                    details['hostname'] = data['outputs'][0]['states'][0]['results'][0]['assets'][0]['hostname']
                except Exception as e:
                    print('Couldn\'t find AWS metadata for asset', asset)

            return details

    except KeyError as e:
        print('Nessus did not return an expected response when getting details for asset', asset)
        print('Response dictionary:')
        pprint.pprint(details)

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


def main():
    if not os.path.isdir(OUTPUT_FOLDER):
        print('Output folder', OUTPUT_FOLDER, 'does not exist.  Please create this folder.')
        return

    path = OUTPUT_FOLDER + 'AWS-Speltdown-' + datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d') + '.csv'
    print('File will be saved to', path)

    try:
        fileOut = open(path, 'w')
    except PermissionError:
        print('Could not open output file for writing.  Is the file already open in another process?')
        return


    print('Getting plugin IDs')
    pluginIDs = GetSpeltdownPlugins()
    print('Found', len(pluginIDs), 'Meltdown/Spectre-related plugins')
    print('Getting affected assets')
    affectedAssets = GetAffectedAssets(pluginIDs)
    print('Found', len(affectedAssets), 'assets affected by Meltdown/Spectre')
    print('Getting asset details')
    assetDetails = GetAssetDetails(affectedAssets)
    zeusHostList = GetHostsFromZeus()
    zeusHosts = {host['id']: host for host in zeusHostList}

    fields = ['Instance ID', 'Agent Name 1', 'Agent Name 2', 'Host Name', 'OS', 'Last Seen', 'Project']
    finalList = []
    for asset in assetDetails:
        assetInfo = {}
        assetInfo['Instance ID'] = asset['aws_ec2_instance_id'][0]
        assetInfo['Agent Name 1'] = asset['agent_name'][0]
        assetInfo['Agent Name 2'] = ''
        assetInfo['Host Name'] = asset['hostname']
        if len(asset['agent_name']) > 1:
            assetInfo['Agent Name 2'] = asset['agent_name'][1]
        assetInfo['Last Seen'] = asset['last_seen']
        assetInfo['OS'] = asset['OS']
        assetInfo['Project'] = zeusHosts.get(asset['aws_ec2_instance_id'][0], {}).get('project', 'UNKNOWN')
        finalList.append(assetInfo)

    print('Sorting data')
    finalList.sort(key=lambda host: host['Instance ID'])
    finalList.sort(key=lambda host: host['Host Name'])
    finalList.sort(key=lambda host: host['Project'])

    print('Writing to', path)
    mycsv = csv.DictWriter(fileOut, lineterminator='\n', fieldnames=fields, quoting=csv.QUOTE_MINIMAL)
    mycsv.writeheader()
    for row in finalList:
        mycsv.writerow(row)

    fileOut.close()

if __name__ == '__main__':
    main()