import requests
import json
import time
from pathlib import Path

class _ip2whois():
    
    def __init__(self, apiToken, ca=None, requestTimeout=30):
        self.requestTimeout = requestTimeout
        self.apiToken = apiToken
        if ca:
            self.ca = Path(ca)
        else:
            self.ca = None

    def apiCall(self,url,methord="GET",data=None):
        kwargs={}
        kwargs["timeout"] = self.requestTimeout
        if self.ca:
            kwargs["verify"] = self.ca
        try:
            if methord == "GET":
                response = requests.get(url, **kwargs)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            return 0, "Connection Timeout"
        if response.status_code == 200 or response.status_code == 202:
            return json.loads(response.text), response.status_code
        return None, response.status_code

    def whois(self,domainName):
        url = "https://api.ip2whois.com/v1?key={0}&domain={1}".format(self.apiToken,domainName)
        response, statusCode = self.apiCall(url)
        return response

   