import requests
import json
import urllib
from st2actions.runners.pythonrunner import Action

class VirusTotal(Action):
    def run(self, apikey, ip):
	url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
	parameters = {'ip': ip, 'apikey': apikey}
	response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
	response_dict = json.loads(response)
	return (True, response_dict)

