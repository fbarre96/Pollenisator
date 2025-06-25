"""A plugin to parse nuclei results"""

from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.plugins.plugin import Plugin
import json


def parse(opened_file):
    """
    Args:
        opened_file: maybe nuclei file
   
    Example of output :
{"template-id":"mongodb-unauth","info":{"name":"Unauth MongoDB Disclosure","author":["pdteam"],"tags":["network","mongodb"],"reference":["https://github.com/orleven/tentacle"],"level":"high"},"type":"network","host":"localhost:27017","matched-at":"localhost:27017","timestamp":"2021-11-09T11:34:57.756466525+01:00"}
{"template-id":"phpinfo-files","info":{"name":"phpinfo Disclosure","author":["pdteam","daffainfo","meme-lord","dhiyaneshdk"],"tags":["config","exposure"],"reference":null,"level":"low"},"type":"http","host":"http://localhost","matched-at":"http://localhost/phpinfo.php","extracted-results":["5.5.9"],"timestamp":"2021-11-09T11:34:58.860666065+01:00","curl-command":"curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36' 'http://localhost/phpinfo.php'"}
    """
    ret = {}
    for line in opened_file:
        if line.strip() == "":
            continue
        try:
            data = json.loads(line)
            if "template-id" in data and "info" in data and "name" in data["info"] and "author" in data["info"] and "tags" in data["info"]:
                host = data.get("host", "")
                if data.get("type", "") == "dns":
                    if host.endswith("."):
                        host = host[:-1]
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
    severities = ["none","info","low", "medium", "high", "critical"]
    for host, data in ret.items():
        data.sort(key=lambda elem: severities.index(elem["info"].get("level",elem["info"].get("severity", "none"))), reverse=True)
    return ret


class Nuclei(Plugin):
    default_bin_names = ["nuclei", "nuclei.py"]
    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " -j -o "

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

    def getTags(self):
        """Returns a list of tags that can be added by this plugin
        Returns:
            list of strings
        """
        return {"info-nuclei": Tag("info-nuclei", level="info"),
                "todo-nuclei-level": Tag("todo-nuclei-level", "orange", level="medium"),
                "todo-high-nuclei-level": Tag("todo-high-nuclei-level", "red", level="high")}

    def Parse(self, pentest, file_opened, **kwargs):
        """
        Parse a opened file to extract information
        Args:
            file_opened: the open file
            kwargs: not used
        Returns:
            a tuple with 4 values (All set to None if Parsing wrong file): 
                0. notes: notes to be inserted in tool giving direct info to pentester
                1. tags: a list of tags to be added to tool 
                2. lvl: the level of the command executed to assign to given targets
                3. targets: a list of composed keys allowing retrieve/insert from/into database targerted objects.
        """
        if kwargs.get("ext", "").lower() != self.getFileOutputExt():
            return None, None, None, None
        parsed_by_hosts = parse(file_opened)
        print("PARSEDBYHOSTS", parsed_by_hosts)
        if parsed_by_hosts is None:
            return None, None, None, None
        tags = [self.getTags()["info-nuclei"]]
        cumulative_notes = []
        targets = {}
        for parsed_host in parsed_by_hosts:
            host = parsed_host
            findings = parsed_by_hosts[parsed_host]
            targets["ip"] = {"ip":host}
            notes = "host:"+str(host)+"\n"
            for finding in findings:
                notes += finding["info"]["name"]+" ("+finding["info"].get("level", finding["info"].get("severity", "none"))+") "+finding["info"].get("description", "")+"\n"
            for finding in findings:
                if finding["info"].get("level", finding["info"].get("severity", "none")) in ["medium"]:
                    tags = [self.getTags()["todo-nuclei-level"]]
                if finding["info"].get("level", finding["info"].get("severity", "none")) in ["critical","high"]:
                    tags = [self.getTags()["todo-high-nuclei-level"]]
            ip_o = Ip(pentest).initialize(host, notes, infos={"plugin":Nuclei.get_name(), "findings":findings})
            # Add a tags to the ip object
            nuclei_tag = Tag("used-nuclei", level="info")
            inserted = ip_o.addInDb()
            ip_o.addTag(nuclei_tag)
            if not inserted["res"]:
                ip_o = Ip.fetchObject(pentest, {"_id": inserted["iid"]})
                if ip_o is not None:
                    ip_o.notes += "\nNuclei:\n"+notes
                    ip_o.infos = {"plugin":Nuclei.get_name(), "findings":findings}
                    ip_o.updateInDb()
                
            cumulative_notes.append(notes+"\n")
        notes = "\n".join(cumulative_notes)

        return notes, tags, "ip", targets
