# summary_of_vulns.py
# Created by DJ Wiza and Derek Hill
#
# Quick aggregate output of all vulnerabilities in the last 2 days
import urllib.parse
import urllib.request
import json
import datetime
import os #remove if not running on corp network

os.environ['http_proxy'] = '<insert proxy server here>'  #remove if not running on corp network
os.environ['https_proxy'] = '<insert proxy server here>' #remove if not running on corp network

def SaveAssetVulnerabilities(headers, nessusBaseURL, outputFolder):
    print('Looking up asset vulnerabilities')
    # Added ?date_range=2 to limit to systems seen in the last 2 days, if you want complete data simply remove
    # To change the number of days, simply change the data_range= parameter (see next line)
    response = getJsonFromRequest(nessusBaseURL + '/workbenches/assets/vulnerabilities?date_range=2', headers)
    # This next section is to take the output from the API call that contains arrays and store the values in separate columns.
    assets = response['assets']
    # Breaking down the list of fqdn's and IP's into separate colums
    num_of_crits = 0
    num_of_highs = 0
    num_of_meds = 0
    num_of_lows = 0

    for asset in assets:
        # Breaking down the list of vulnerabilities into separate columns, creating a total column and adding all the values
        num_of_lows += asset['severities'][1]['count']
        num_of_meds += asset['severities'][2]['count']
        num_of_highs += asset['severities'][3]['count']
        num_of_crits += asset['severities'][4]['count']
    currentdate = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d')
    print(num_of_crits, num_of_highs, num_of_meds, num_of_lows)
    f=open(outputFolder + '/vulnerability-totals-' + currentdate +'.txt' , 'w')
    f.write('Criticals: ' + str(num_of_crits) + '\n')
    f.write('Highs: ' + str(num_of_highs) + '\n')
    f.write('Mediums: ' + str(num_of_meds) + '\n')
    f.write('Lows: ' + str(num_of_lows) + '\n')
    f.close()

# def main(args):
def main():
    accessKey = "<insert keys here>"
    secretKey = "<insert keys here>"
    nessusBaseURL = "https://cloud.tenable.com"
    outputFolder = "C:/Temp/nessus/"
    # Build request header with access tokens.
    headers = {'X-ApiKeys': 'accessKey=' + accessKey + '; secretKey=' + secretKey}
    SaveAssetVulnerabilities(headers, nessusBaseURL, outputFolder)
    currentdate = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d')


# Takes a url and header and returns a json object from the http response.
def getJsonFromRequest(url, headers):
    req = urllib.request.Request(url, headers=headers)
    response = None
    for attempt in range(1, 4):
        try:
            response = urllib.request.urlopen(req)
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


if __name__ == "__main__":
    main()