from core import plugin, model

class _ip2whois(plugin._plugin):
    version = 0.1

    def install(self):
        # Register models
        model.registerModel("ip2whois","_ip2whois","_action","plugins.ip2whois.models.action")
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("ip2whois","_ip2whois","_action","plugins.ip2whois.models.action")
        return True

    def upgrade(self,LatestPluginVersion):
        pass
        #if self.version < 0.2:
