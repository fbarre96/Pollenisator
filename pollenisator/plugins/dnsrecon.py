"""A plugin to parse dnsrecon scan"""

# 1. Imports
import re
import json
from pollenisator.server.ServerModels.Ip import ServerIp
from pollenisator.plugins.plugin import Plugin


class dnsrecon(Plugin):
    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " -j "

    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".json"

    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        return commandExecuted.split(self.getFileOutputArg())[-1].strip()

    def Parse(self, pentest, file_opened, **kwargs):
        """
        Parse a opened file to extract information
        Example:
[       
    {
        "arguments": "./dnsrecon.py -r 10.0.0.0/24 -j /home/barre/test.json",
        "date": "2020-01-06 11:43:37.701513",
        "type": "ScanInfo"
    },
    {
        "address": "10.0.0.1",
        "name": "_gateway",
        "type": "PTR"
    },
    {
        "address": "10.0.0.77",
        "name": "barre-ThinkPad-E480",
        "type": "PTR"
    },
    {
        "address": "10.0.0.77",
        "name": "barre-ThinkPad-E480.local",
        "type": "PTR"
    }
]
        Args:
            file_opened: the open file
            _kwargs: not used
        Returns:
            a tuple with 4 values (All set to None if Parsing wrong file): 
                0. notes: notes to be inserted in tool giving direct info to pentester
                1. tags: a list of tags to be added to tool 
                2. lvl: the level of the command executed to assign to given targets
                3. targets: a list of composed keys allowing retrieve/insert from/into database targerted objects.
        """
        if kwargs.get("ext", "").lower() != self.getFileOutputExt():
            return None, None, None, None
        notes = ""
        tags = []
        countInserted = 0
        try:
            dnsrecon_content = json.loads(file_opened.read().decode("utf-8"))
        except json.decoder.JSONDecodeError:
            return None, None, None, None
        except UnicodeDecodeError:
            return None, None, None, None
        try:
            if isinstance(dnsrecon_content, list) and len(dnsrecon_content) == 0:
                return None, None, None, None
            if not isinstance(dnsrecon_content[0], dict):
                return None, None, None, None
            if dnsrecon_content[0].get("type", "") != "ScanInfo":
                return None, None, None, None
            if dnsrecon_content[0].get("date", "") == "":
                return None, None, None, None
        except:
            return None, None, None, None
        for records in dnsrecon_content[1:]:
            if not isinstance(records, list):
                records = [records]
            for record in records:
                ip = record["address"]
                name = record["name"]
                infosToAdd = {"hostname": [name], "plugin":dnsrecon.get_name()}
                ip_m = ServerIp(pentest).initialize(ip, infos=infosToAdd)
                ip_m.addInDb()
                infosToAdd = {"ip": [ip], "plugin":dnsrecon.get_name()}
                ip_m = ServerIp(pentest).initialize(name, infos=infosToAdd)
                insert_ret = ip_m.addInDb()
                # failed, domain is out of scope
                if not insert_ret["res"]:
                    notes += name+" exists but already added.\n"
                    ip_m = ServerIp.fetchObject(pentest, {"_id": insert_ret["iid"]})
                    existing_ips = ip_m.infos.get("ip", [])
                    if not isinstance(existing_ips, list):
                        existing_ips = [existing_ips]
                    infosToAdd = {"ip": list(set([ip] +existing_ips))}
                    ip_m.updateInfos(infosToAdd)
                else:
                    countInserted += 1
                    notes += name+" inserted.\n"
        return notes, tags, "wave", {"wave": None}
