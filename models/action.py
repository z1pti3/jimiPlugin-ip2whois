from core.models import action
from core import auth, db, helpers

from plugins.ip2whois.includes import ip2whois

class _ip2whois(action._action):
    apiToken = str()
    domainName = str()

    def run(self,data,persistentData,actionResult):
        domainName = helpers.evalString(self.domainName,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = ip2whois._ip2whois(apiToken).whois(domainName)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["whois"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from ip2whois API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_ip2whois,self).setAttribute(attr,value,sessionData=sessionData)
