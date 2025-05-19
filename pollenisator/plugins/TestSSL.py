"""A plugin to parse testssl.sh"""
import re
from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.plugins.plugin import Plugin
from pollenisator.core.models.defect import Defect


warning_regex = re.compile(r"^\"([^\"]*)\", ?\"([^\"]*)\", ?\"([^\"]*)\", ?\"(OK|INFO|NOT ok|WARN|LOW|MEDIUM|HIGH|CRITICAL)\", ?\"([^\"]*)\", ?\"([^\"]*)\", ?\"([^\"]*)\"$")

def bulk_insertions(pentest, ips_to_add, ports_to_add):
    """Bulk insertions of ips and ports
    """
    Ip.bulk_insert(pentest, ips_to_add, look_scopes=True)
    Port.bulk_insert(pentest, ports_to_add)
    

def parseWarnings(pentest, file_opened):
    """
    Parse the result of a testssl json output file
        Args:
            file_opened:  the opened file reference

        Returns:
            Returns a tuple with (None values if not matching a testssl output):
                - a list of string for each testssl NOT ok, WARN, or MEDIUM warnings
                - a dict of targeted objects with database id as key and a unique key as a mongo search pipeline ({})
    """
    targets = {}
    missconfiguredHosts = {}
    
    firstLine = True
    ips_to_add = {}
    ports_to_add = {}
    for line in file_opened:
        line = line.decode("utf-8", errors="ignore").strip()
        if firstLine:
            if line != '"id", "fqdn/ip", "port", "severity", "finding", "cve", "cwe"' and \
                    line != '"id","fqdn/ip","port","severity","finding","cve","cwe"':
                return None, None
            firstLine = False
            continue
        # Search ip in file
        warn = re.search(
            warning_regex, line)
        if warn is not None:
            subject = warn.group(1)
            ip = warn.group(2)
            domain = None
            port = warn.group(3)
            level = warn.group(4)
            details = warn.group(5)
            cve = warn.group(6)
            cwe = warn.group(7)
            # crop details if too long
            if len(details) > 50:
                details = details[:25]+" [...] "+details[-25:]
            if "/" in ip:
                domain = ip.split("/")[0]
                ip = "/".join(ip.split("/")[1:])
                if (ip.strip() != "") and ip not in ips_to_add:
                    ips_to_add[ip] = Ip(pentest).initialize(ip, infos={"plugin":TestSSL.get_name(), "FQDN": domain})
                    ips_to_add[ip] = Ip(pentest).initialize(ip, infos={"plugin":TestSSL.get_name(), "FQDN": domain})
                if (domain.strip() != "") and domain not in ips_to_add:
                    ips_to_add[domain] = Ip(pentest).initialize(domain, infos={"plugin":TestSSL.get_name(), "ip": ip})
                if ip+str(port) not in ports_to_add:
                    ports_to_add[ip+str(port)] = Port(pentest).initialize(ip, port, "tcp", "ssl", infos={"plugin":TestSSL.get_name(), "FQDN": domain})
                if domain+str(port) not in ports_to_add:
                    ports_to_add[domain+str(port)] = Port(pentest).initialize(domain, port, "tcp", "ssl", infos={"plugin":TestSSL.get_name(), "ip": ip})
            if ip.strip() == "":
                continue
            else:
                if ip not in ips_to_add:
                    ips_to_add[ip] = Ip(pentest).initialize(ip, infos={"plugin":TestSSL.get_name()})
                if ip+str(port) not in ports_to_add:
                    ports_to_add[ip+str(port)] = Port(pentest).initialize(ip, port, "tcp", "ssl", infos={"plugin":TestSSL.get_name()})

            information = {"defect": subject, "criticity": level, "details": details}
            if cve.strip() != "":
                information["cve"] = cve
            if cwe.strip() != "":
                information["cwe"] = cwe
            if domain is not None:
                missconfiguredHosts[domain] = missconfiguredHosts.get(domain, {})
                missconfiguredHosts[domain][port] = missconfiguredHosts[domain].get(port, [])
                missconfiguredHosts[domain][port].append(information)
            else:
                missconfiguredHosts[ip] = missconfiguredHosts.get(ip, {})
                missconfiguredHosts[ip][port] = missconfiguredHosts[ip].get(port, [])
                missconfiguredHosts[ip][port].append(information)
    bulk_insertions(pentest, list(ips_to_add.values()), list(ports_to_add.values()))
    cache = {}
    for ip, _ in missconfiguredHosts.items():
        if ip.strip() != "":
            print("IP : ", ip)
            for item, value in missconfiguredHosts[ip].items():
                print("ITEM : ", item)
                if isinstance(value, dict):
                    # Means that the item is a domain
                    print("VALUE : ", value)
                    for port in value.keys():
                        print("PORT : ", port)
                        if (ip, port) in cache:
                            p_o = cache[(ip, port)]
                        else:
                            p_o = Port.fetchObject(pentest, {"ip": ip, "port": port, "proto": "tcp"})
                            cache[(ip, port)] = p_o
                        print("OBJET PORT : ", p_o)
                        targets[str(p_o.getId())] = {
                            "ip": ip, "port": port, "proto": "tcp"}
                        notes = ""
                        for warning in value[port]:
                            notes += warning["defect"] + " : " + warning["details"] + " (Criticity : " + warning["criticity"] + ")\n"
                            if "cve" in warning:
                                notes += "CVE  : " + warning["cve"] + "\n"
                            if "cwe" in warning:
                                notes += "CWE : " + warning["cwe"] + "\n"
                        p_o.addTag(Tag("SSL/TLS-flaws", None, "low", notes=notes))
                        p_o.updateInfos({TestSSL.get_name(): missconfiguredHosts[ip][item][port]})
                else:
                    # Means that the item is a port
                    print("VALUE : ", value)
                    port = item
                    if (ip, port) in cache:
                        p_o = cache[(ip, port)]
                    else:
                        p_o = Port.fetchObject(pentest, {"ip": ip, "port": port, "proto": "tcp"})
                        cache[(ip, port)] = p_o
                    print("OBJET PORT : ", p_o)
                    targets[str(p_o.getId())] = {
                        "ip": ip, "port": item, "proto": "tcp"}
                    notes = ""
                    for warning in value:
                        notes += warning["defect"] + " : " + warning["details"] + " (Criticity : " + warning["criticity"] + ")\n"
                        if "cve" in warning:
                            notes += "CVE  : " + warning["cve"] + "\n"
                        if "cwe" in warning:
                            notes += "CWE : " + warning["cwe"] + "\n"
                    p_o.addTag(Tag("SSL/TLS-flaws", None, "low", notes=notes))
                    p_o.updateInfos({TestSSL.get_name(): missconfiguredHosts[ip][item]})
        if firstLine:
            return None, None
    return str(len(missconfiguredHosts.keys()))+" misconfigured hosts found. Defects created.", targets

class TestSSL(Plugin):
    """A plugin to parse testssl.sh output files"""

    default_bin_names = ["testssl", "testssl.sh"]
    def getFileOutputArg(self):
        """
        Return the expected argument for the tool that will create an output file.
        Returns:
            Returns a string containing the argument to look for, with a space at the beginning and at the end.
        """
        return " --csvfile "

    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".csv"

    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        return commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0]

    def changeCommand(self, command, outputDir, toolname):
        """
        Summary: Complete the given command with the tool output file option and filename absolute path.
        Args:
            * command : the command line to complete
            * outputDir : the directory where the output file must be generated
            * toolname : the tool name (to be included in the output file name)
        Return:
            The command complete with the tool output file option and filename absolute path.
        """
        # default is append at the end, testssl requires the target at the end
        if self.getFileOutputArg() not in command:
            args = command.split(" ")
            return " ".join(args[:-1]) + self.getFileOutputArg()+outputDir+toolname + " "+args[-1]
        return command

    def getTags(self):
        """Returns a list of tags that can be added by this plugin
        Returns:
            list of strings
        """
        return {"SSL/TLS-flaws": Tag("SSL/TLS-flaws", level="low")}
    
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
        notes, targets = parseWarnings(pentest, file_opened)
        if notes is None:
            return None, None, None, None
        return notes, [], "port", targets
