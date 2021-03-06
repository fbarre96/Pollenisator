"""A plugin to parse testssl.sh"""
import re

from core.plugins.plugin import Plugin
from server.ServerModels.Ip import ServerIp
from server.ServerModels.Port import ServerPort
from server.ServerModels.Defect import ServerDefect

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
        line = line.decode("utf-8")
        if firstLine:
            if line.strip() != '"id", "fqdn/ip", "port", "severity", "finding", "cve", "cwe"' and \
                    line.strip() != '"id","fqdn/ip","port","severity","finding","cve","cwe"':
                return None, None
            firstLine = False
            continue
        # Search ip in file
        warn = re.search(
            r"^\"[^\"]*\", ?\"([^\"]*)\", ?\"([^\"]*)\", ?\"(OK|INFO|NOT ok|WARN|LOW|MEDIUM|HIGH|CRITICAL)\", ?\"[^\"]*\", ?\"[^\"]*\", ?\"[^\"]*\"$", line)
        if warn is not None:
            ip = warn.group(1)
            domain = None
            port = warn.group(2)
            notes = warn.group(3)
            if "/" in ip:
                domain = ip.split("/")[0]
                ip = "/".join(ip.split("/")[1:])
                ServerIp().initialize(domain).addInDb()
                ServerPort().initialize(domain, port, "tcp", "ssl").addInDb()
            ServerIp().initialize(ip).addInDb()
            ServerPort().initialize(ip, port, "tcp", "ssl").addInDb()
            if notes not in ["OK", "INFO"]:
                missconfiguredHosts[ip] = missconfiguredHosts.get(ip, {})
                missconfiguredHosts[ip][port] = missconfiguredHosts[ip].get(port, [
                ])
                missconfiguredHosts[ip][port].append(notes+" : "+line)
                if domain is not None:
                    missconfiguredHosts[domain] = missconfiguredHosts.get(
                        domain, {})
                    missconfiguredHosts[domain][port] = missconfiguredHosts[domain].get(
                        port, [])
                    missconfiguredHosts[domain][port].append(notes+" : "+line)
    for ip in missconfiguredHosts.keys():
        for port in missconfiguredHosts[ip].keys():
            p_o = ServerPort.fetchObject(pentest, {"ip": ip, "port": port, "proto": "tcp"})
            targets[str(p_o.getId())] = {
                "ip": ip, "port": port, "proto": "tcp"}
            missconfiguredHosts[ip][port].sort()
            notes = "\n".join(missconfiguredHosts[ip][port])
            res, _ = ServerDefect().initialize(ip, port, "tcp", "Défauts d'implémentation du SSL/TLS",
                                         "Très difficile", "Majeur", "Important", "N/A", ["Socle"], notes=notes, proofs=[]).addInDb()
            if not res:
                p_o.updateInfos({"compliant": "False"})
                defect_o = ServerDefect.fetchObject(
                    {"ip": ip, "title": "Défauts d'implémentation du SSL/TLS", "port": port, "proto": "tcp"})
                defect_o.notes += notes
                defect_o.update()
    if firstLine:
        return None, None
    return str(len(missconfiguredHosts.keys()))+" misconfigured hosts found. Defects created.", targets


class TestSSL(Plugin):
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
        notes, targets = parseWarnings(pentest, file_opened)
        if notes is None:
            return None, None, None, None
        return notes, [], "port", targets
