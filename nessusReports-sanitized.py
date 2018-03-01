#nessusReports.py
#
# Provided without any support, make changes as needed for your enviornment
#
#Derek Hill <derek.hill@hp.com>
#Syler Clayton <Syler.Clayton@hp.com> & DJ Wiza <dj.Wiza@hp.com>
#April 7, 2017
#usage: nessusReports.py [-h] nessusBaseURL accessKey secretKey outputFolder
#Performs various actions with the Nessus Cloud API
import urllib.parse
import urllib.request
import json
import csv
import re
import multiprocessing
import datetime
import os

os.environ['HTTPS_PROXY'] = 'http://<insert your proxy URL here if needed>:8080' #comment out if no proxy is used

def getData(item):
    assetID, i, listLen, headers, baseURL = item
    print('Looking up info for asset ID: ', assetID, ' (', i, '/', listLen, ')', sep='')
    jsonResponse = getJsonFromRequest(baseURL + '/workbenches/assets/' + assetID + '/info', headers)
    if jsonResponse is not None:
        return jsonResponse['info']
    return None

def SaveAssetVulnerabilities(headers, nessusBaseURL, outputFolder):
    print('Looking up asset vulnerabilities')
    #Added ?date_range=7 to limit to systems seen in the last 7 days, if you want complete data simply remove
    response = getJsonFromRequest(nessusBaseURL + '/workbenches/assets/vulnerabilities?date_range=1', headers)
    #This next section is to take the output from the API call that contains arrays and store the values in separate columns.
    assets = response['assets']
    #Breaking down the list of fqdn's and IP's into separate colums
    for asset in assets:
        asset['fqdn-1'] = asset['fqdn'] [0]
        asset['ipv4-1'] = asset['ipv4'][0]
        if len(asset['fqdn']) > 1:
            asset['fqdn-2'] = asset['fqdn'][1]
        else:
            asset['fqdn-2'] = ""
        if len(asset['fqdn']) > 2:
            asset['fqdn-3'] = asset['fqdn'][2]
        else:
            asset['fqdn-3'] = ""
        if len(asset['ipv4']) > 1:
            asset['ipv4-2'] = asset['ipv4'][1]
        else:
            asset['ipv4-2'] = ""
        if len(asset['ipv4']) > 2:
            asset['ipv4-3'] = asset['ipv4'][2]
        else:
            asset['ipv4-3'] = ""
        #asset['Info'] = asset['severities'][0]['count'] <--Removed Info column as it is not used
        #Breaking down the list of vulnerabilities into separate columns, creating a total column and adding all the values
        asset['Low'] = asset['severities'][1]['count']
        asset['Medium'] = asset['severities'][2]['count']
        asset['High'] = asset['severities'][3]['count']
        asset['Critical'] = asset['severities'][4]['count']
        asset['Total'] = asset['Low'] + asset['Medium'] + asset['High'] + asset['Critical']
        #asset['fqdn-1'] = asset['fqdn'][0]
        del asset['severities']
        del asset['fqdn']
        del asset['ipv4']
        del asset['ipv6'] # <--removing for now as we are not using it, will have to add back to 'keys' list if re-enabled
        del asset['agent_name']
        del asset['netbios_name']
    assets = {'assets': assets}
    currentdate = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d')
    print('Saving asset vulnerabilities to asset_vulnerabilities.csv')
    keys = ['id', 'last_seen', 'ipv4-1', 'ipv4-2', 'ipv4-3', 'fqdn-1', 'fqdn-2', 'fqdn-3', 'Low', 'Medium', 'High', 'Critical', 'Total']
    json2csv(assets, outputFolder + 'asset_vulnerabilities-' + currentdate + '.csv', keys=keys)

#def main(args):
def main():
    accessKey="<insert your key here>"
    secretKey="<insert your key here>"
    nessusBaseURL="https://cloud.tenable.com"
    outputFolder="C:/Temp/nessus/"  #location where your files will be saved
    #Build request header with access tokens.
    headers = {'X-ApiKeys': 'accessKey=' + accessKey + '; secretKey=' + secretKey}

    SaveAssetVulnerabilities(headers, nessusBaseURL, outputFolder)

    currentdate = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d')

    #Get agent info for scanner 1 and save to agents.csv
    print('Looking up agent info for scanner 1')
    agentJsonResponse=getJsonFromRequest(nessusBaseURL+'/scanners/1/agents',headers)
    print('Saving agent info to agents.csv')
    json2csv(agentJsonResponse, outputFolder + '/agents-' + currentdate + '.csv')

    #get vulnerbility info and save to vulnerabilities.csv
    print('Looking up vulnerability info')
    vulnerabilityJsonResponse = getJsonFromRequest(nessusBaseURL + '/workbenches/vulnerabilities', headers)
    print('Saving vulnerability info to vulnerabilities.csv')
    json2csv(vulnerabilityJsonResponse, outputFolder + '/vulnerabilities-' + currentdate +'.csv')

    # no longer used, but left in, just in case we want it back
    #Get asset info and save to assets.csv  #no longer used, but left in, just in case we want it back
    # print('Looking up asset info')
    # assetJsonResponse = getJsonFromRequest(nessusBaseURL + '/workbenches/assets?date_range=180', headers)
    # print('Saving asset info to assets.csv')
    # json2csv(assetJsonResponse, outputFolder + '/assets-' + currentdate + '.csv')

    # no longer used, but left in, just in case we want it back
    #get assetID's from asset info
    # print('Parsing asset info to get list of asset IDs')
    # assetIDList=getAssetIDList(assetJsonResponse)

    #loop through the list of assetID's and get information for that asset.
    # old behavior -- over 1,000 files!
    # for assetID in assetIDList:
    #     print('Looking up info for asset ID: '+assetID)
    #     jsonResponse=getJsonFromRequest(args.nessusBaseURL+'/workbenches/assets/'+assetID+'/info',headers)
    #     print('Here is what the response for the asset info looks like. It appears we are getting json back :/')
    #     print(jsonResponse)
    #     print('Saving info for asset ID: '+assetID+' to asset_'+assetID+'.csv')
    #     print('Currently failing here trying to save the asset ID info to a csv')
    #     json2csv(jsonResponse,args.outputFolder+'/asset_'+assetID+'.csv')

    # new behavior - single file!
    # assetDetails = []
    # assetIDList = assetIDList

    # pool = multiprocessing.Pool(8)
    # assetDetails = pool.map(getData, list(zip(assetIDList,
    #                                           list(range(1, len(assetIDList) + 1)),
    #                                           [len(assetIDList)] * len(assetIDList),
    #                                           [headers] * len(assetIDList),
    #                                           [nessusBaseURL] * len(assetIDList)
    #                                           )))

    # Remove failure cases
    # before = len(assetDetails)
    # assetDetails = [asset for asset in assetDetails if asset is not None]
    # if len(assetDetails) != before:
    #     print("WARNING:", len(assetDetails) - before, "asset details were removed!")

    # assetDetails = [getData(item) for item in list(zip(assetIDList,
    #                                           list(range(1, len(assetIDList) + 1)),
    #                                           [len(assetIDList)] * len(assetIDList),
    #                                           [headers] * len(assetIDList),
    #                                           [nessusBaseURL] * len(assetIDList)
    #                                           ))]
    # for i, assetID in enumerate(assetIDList, start=1):
    #     print('Looking up info for asset ID: ', assetID, ' (', i, '/', len(assetIDList), ')', sep='')
    #     jsonResponse=getJsonFromRequest(args.nessusBaseURL+'/workbenches/assets/'+assetID+'/info',headers)
    #     assetDetails.append(jsonResponse['info'])

    # print('Saving all asset details to ', outputFolder, '/assetDetails.csv', sep='')
    # json2csv({'info': assetDetails}, outputFolder + '/assetDetails-' + currentdate + '.csv')

#Takes a url and header and returns a json object from the http response.
def getJsonFromRequest(url,headers):
    req = urllib.request.Request(url, headers=headers)
    response = None
    for attempt in range(1, 4):
        try:
            response=urllib.request.urlopen(req)
            break
        except Exception as e:
            print("An exception occured getting URL", url, ":")
            print(repr(e))

    if response is None:
        print("Could not get URL", url, "after 3 attempts.  Giving up.")
        return None

    jsonResponse = response.read().decode('utf-8')
    json_obj = json.loads(jsonResponse)
    return json_obj

#Returns a list of Asset IDs from /scanners/1/agents
def getAssetIDList(myjson):
    assetIDList=[]
    myjson = myjson[list(myjson.keys())[0]]
    for i in myjson:
        for k,v in i.items():
            if k=='id':
                assetIDList.append(v)
    return assetIDList
    

#Takes a json object and .csv file output names as params.
def json2csv(myjson,fileOutName,keys=None):
    fileOut=open(fileOutName, 'w')
    myjson = myjson[list(myjson.keys())[0]]

    if type(myjson) == list:
        if keys is None:
            keys = []
            for row in myjson:
                keys += [key for key in row.keys() if key not in keys]
        print('CSV columns: ', ', '.join(keys))
        mycsv = csv.DictWriter(fileOut, lineterminator='\n', fieldnames=keys, quoting=csv.QUOTE_MINIMAL)
        mycsv.writeheader()
        for row in myjson:
            mycsv.writerow(row)
    elif type(myjson) == dict:
        if keys is None:
            keys = list(myjson.keys())
        mycsv = csv.DictWriter(fileOut, lineterminator='\n', fieldnames=keys, quoting=csv.QUOTE_MINIMAL)
        mycsv.writeheader()
        mycsv.writerow(myjson)
    else:
        raise TypeError('myjson was a %s when it should have been a list or dict' % (str(type(myjson))))

    fileOut.close()
    return

#Attempting to get alternative json parser to work.
#https://github.com/AgamAgarwal/json2csv/blob/master/json2csv.py
NESTING_SEP = '/'
FIELD_SEP = '\t'
def encode(s):
    return s.replace('\n', ' ').encode('utf-8') if type(s) not in [int, float] else s

def flatten(data, prefix = ''):
    flattened = {}

    for key in data:
        value = data[key]
        if type(value) is dict:
            x = flatten(value, prefix = prefix + key + NESTING_SEP)
            flattened.update(x)
        elif type(value) is list:
            x = flatten(dict(zip(map(str, range(len(value))), value)), prefix = prefix + key + NESTING_SEP)
            flattened.update(x)
        else:
            flattened[prefix + key] = encode(value)
        return flattened

def json2csvTest(myjson,fileOutName):
    output = open(fileOutName, 'w')
    columns = set()
    flattened_all = []
    data = myjson
    flattened = flatten(data)
    columns = columns.union(flattened.keys())
    headers = sorted(list(columns))

    writer = csv.DictWriter(output, delimiter = FIELD_SEP, fieldnames = headers)
    writer.writeheader()
    print(flattened)
    for flattened in flattened_all:
        writer.writerow(flattened)

if __name__ == "__main__":
    #Argument parsing
    #parser = argparse.ArgumentParser()
    #parser.add_argument('nessusBaseURL', help='Base URL for Nessus cloud. e.g. https://cloud.tenable.com')
    #parser.add_argument('accessKey', help='Access Key for Nessus cloud.')
    #parser.add_argument('secretKey', help='Secret Key for Nessus cloud.')
    #parser.add_argument('outputFolder', help='Folder to output CSVs.')
    #args = parser.parse_args()
    #main(args)
    main()
