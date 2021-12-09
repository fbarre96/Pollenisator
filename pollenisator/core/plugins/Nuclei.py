"""A plugin to parse nuclei results"""

from pollenisator.server.ServerModels.Defect import ServerDefect
from pollenisator.server.ServerModels.Ip import ServerIp
from pollenisator.server.ServerModels.Port import ServerPort
from pollenisator.core.plugins.plugin import Plugin
import json


def parse(opened_file):
    """
    Args:
        opened_file: maybe nuclei file
   
    Example of output :
{"template-id":"mongodb-unauth","info":{"name":"Unauth MongoDB Disclosure","author":["pdteam"],"tags":["network","mongodb"],"reference":["https://github.com/orleven/tentacle"],"severity":"high"},"type":"network","host":"localhost:27017","matched-at":"localhost:27017","timestamp":"2021-11-09T11:34:57.756466525+01:00"}
{"template-id":"phpinfo-files","info":{"name":"phpinfo Disclosure","author":["pdteam","daffainfo","meme-lord","dhiyaneshdk"],"tags":["config","exposure"],"reference":null,"severity":"low"},"type":"http","host":"http://localhost","matched-at":"http://localhost/phpinfo.php","extracted-results":["5.5.9"],"timestamp":"2021-11-09T11:34:58.860666065+01:00","curl-command":"curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36' 'http://localhost/phpinfo.php'"}
    """
    ret = {}
    for line in opened_file:
        if line.strip() == "":
            continue
        try:
            data = json.loads(line)
            if "template-id" in data and "info" in data and "name" in data["info"] and "author" in data["info"] and "tags" in data["info"]:
                host = data["host"]
                if data["type"] == "network":
                    parts = data["host"].split(":")
                    if len(parts) == 2:
                        host = parts[0]
                elif data["type"] == "http":
                    host = host.split("://")[-1]
                    parts = host.split(":")
                    if len(parts) == 2:
                        host = parts[0]
                ret[host] = ret.get(host,[]) + [data]
            else:
                return None
        except:
            return None
    if len(ret) == 0:
        return None
    severities = ["info","low", "medium", "high", "critical"]
    for host, data in ret.items():
        data.sort(key=lambda elem: severities.index(elem["info"]["severity"]), reverse=True)
    return ret


class Nuclei(Plugin):
    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " -json -o "

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
        return commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0]

    def Parse(self, pentest, file_opened, **_kwargs):
        """
        Parse a opened file to extract information
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
        parsed_by_hosts = parse(file_opened)
        if parsed_by_hosts is None:
            return None, None, None, None
        tags = ["todo"]
        cumulative_notes = []
        targets = {}
        for parsed_host in parsed_by_hosts:
            host = parsed_host
            findings = parsed_by_hosts[parsed_host]
            targets["ip"] = {"ip":host}
            notes = "host:"+str(host)+"\n"
            for finding in findings:
                notes += finding["info"]["name"]+" ("+finding["info"]["severity"]+") "+finding["info"].get("description", "")+"\n"
            for finding in findings:
                if finding["info"]["severity"] in ["medium", "high", "critical"]:
                    tags = ["Interesting"]
            ip_o = ServerIp().initialize(host, notes)
            inserted = ip_o.addInDb()
            if not inserted["res"]:
                ip_o = ServerIp.fetchObject(pentest, {"_id": inserted["iid"]})
                ip_o.notes += "\nNuclei:\n"+notes
                ip_o.update()
            cumulative_notes.append(notes+"\n")
            
            
        notes = "\n".join(cumulative_notes)

        return notes, tags, "ip", targets
