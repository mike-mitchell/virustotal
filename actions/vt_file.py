import requests
import json
import urllib
import io
import base64
from st2actions.runners.pythonrunner import Action

class VirusTotalFile(Action):
    def run(self, apikey, file_name, file_content):
        params = {'apikey': '-YOUR API KEY HERE-'}
        stream = io.BytesIO(base64.b64decode(file_content['base64']))
        files = {'file': (file_name, stream)}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        json_response = response.json()
        return (True, json_response)


