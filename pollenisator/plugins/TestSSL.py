"""A plugin to parse testssl.sh"""
import re
from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.plugins.plugin import Plugin

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
    for line in file_opened:
        line = line.decode("utf-8", errors="ignore")
        if firstLine:
            if line.strip() != '"id", "fqdn/ip", "port", "severity", "finding", "cve", "cwe"' and \
                    line.strip() != '"id","fqdn/ip","port","severity","finding","cve","cwe"':
                return None, None
            firstLine = False
            continue
        # Search ip in file
        warn = re.search(
            r"^\"([^\"]*)\", ?\"([^\"]*)\", ?\"([^\"]*)\", ?\"(OK|INFO|NOT ok|WARN|LOW|MEDIUM|HIGH|CRITICAL)\", ?\"([^\"]*)\", ?\"([^\"]*)\", ?\"([^\"]*)\"$", line)
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
                details = details[:100]+" [...] "+details[-100:]
            if "/" in ip:
                domain = ip.split("/")[0]
                ip = "/".join(ip.split("/")[1:])
                if ip.strip() != "" and domain.strip() != "":
                    Ip(pentest).initialize(domain, infos={"plugin":TestSSL.get_name()}).addInDb()
                    Port(pentest).initialize(domain, port, "tcp", "ssl", infos={"plugin":TestSSL.get_name()}).addInDb()
            if ip.strip() == "":
                continue
            Ip(pentest).initialize(ip, infos={"plugin":TestSSL.get_name()}).addInDb()
            Port(pentest).initialize(ip, port, "tcp", "ssl", infos={"plugin":TestSSL.get_name()}).addInDb()
            
            if level not in ["OK", "INFO"]:
                information = {"defect": subject, "criticity": level, "details": details}
                if cve.strip() != "":
                    information["cve"] = cve
                if cwe.strip() != "":
                    information["cwe"] = cwe
                missconfiguredHosts[ip] = missconfiguredHosts.get(ip, {})
                missconfiguredHosts[ip][port] = missconfiguredHosts[ip].get(port, [
                ])
                missconfiguredHosts[ip][port].append(information)
                if domain is not None:
                    missconfiguredHosts[domain] = missconfiguredHosts.get(
                        domain, {})
                    missconfiguredHosts[domain][port] = missconfiguredHosts[domain].get(
                        port, [])         
                    missconfiguredHosts[domain][port].append(information)
    for ip, _ in missconfiguredHosts.items():
        if ip.strip() != "":
            for port in missconfiguredHosts[ip].keys():
                p_o = Port.fetchObject(pentest, {"ip": ip, "port": port, "proto": "tcp"})
                targets[str(p_o.getId())] = {
                    "ip": ip, "port": port, "proto": "tcp"}
                notes = ""
                for warning in missconfiguredHosts[ip][port]:
                    notes += warning["defect"] + " : " + warning["details"] + " (Criticity : " + warning["criticity"] + ")\n"
                    if "cve" in warning:
                        notes += "CVE  : " + warning["cve"] + "\n"
                    if "cwe" in warning:
                        notes += "CWE : " + warning["cwe"] + "\n"
                p_o.addTag(Tag("SSL/TLS-flaws", None, "low", notes=notes))
                p_o.updateInfos({TestSSL.get_name(): missconfiguredHosts[domain][port]})
                print("NOTES: ", notes)
        if firstLine:
            return None, None
    return str(len(missconfiguredHosts.keys()))+" misconfigured hosts found. Defects created.", targets


class TestSSL(Plugin):
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
