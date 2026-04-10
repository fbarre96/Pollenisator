"""A plugin to parse sshscan"""

import json
import shlex
from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.plugins.plugin import Plugin
from pollenisator.plugins.plugin_result import PluginResult, InfoUpdate, TagAddition

class SSHAudit(Plugin):
    default_bin_names = ["ssh-audit", "ssh_audit", "ssh_audit.py"]

    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " | tee "

    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".json"
    
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
        command = super().changeCommand(command, outputDir, toolname)
        args = command.split(" ")
        if "-jj" not in args:
            command = args[0] + " -jj " + " ".join(args[1:])
        return command


    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        ouputPath = str(commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0])
        return ouputPath

    def getTags(self):
        """Returns a list of tags that can be added by this plugin
        Returns:
            list of strings
        """
        return {"info-sshaudit": Tag("info-sshaudit"), 
                "CVE-ssh": Tag("CVE-ssh", level="high", color="red"),
                "SSH-flaw": Tag("SSH-flaw", level="low", color="yellow")}

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
            return PluginResult.empty()
        notes = ""
        tags = [self.getTags()["info-sshaudit"]]
        content = file_opened.read().decode("utf-8", errors="ignore")
        targets = {}
        try:
            scan = json.loads(content)
        except json.decoder.JSONDecodeError:
            return PluginResult.empty()
        try:
            if scan.get('additional_notes', None) is None:
                return PluginResult.empty()
            if scan.get("cves", None) is None:
                return PluginResult.empty()
            if scan.get("kex", None) is None:
                return PluginResult.empty()
            if scan.get("enc", None) is None:
                return PluginResult.empty()
            target = scan.get("target", None)
            if target is None:
                return PluginResult.empty()
            target_split = target.split(":")
            if len(target_split) != 2:
                return PluginResult.empty()
            try:
                ip = target_split[0]
                port = int(target_split[1])
            except ValueError:
                return PluginResult.empty()
            
            if ip.strip() == "":
                return PluginResult.empty()
            result = PluginResult(notes=notes, tags=tags, lvl="port", targets=targets)
            result.ips.append(Ip(pentest).initialize(ip, infos={"plugin": SSHAudit.get_name()}))
            result.ports.append(Port(pentest).initialize(ip, port, "tcp", "ssh", infos={"plugin": SSHAudit.get_name()}))
            port_key = {"ip": ip, "port": str(port), "proto": "tcp"}
            notes = ""
            for cve in scan["cves"]:
                if cve.get("cve", None) is not None:
                    notes += f"CVE: {cve['cve']}\n"
                    tags.append(self.getTags()["CVE-ssh"])
            notes += str(scan.get("recommendations",""))           

            targets["sshaudit_" + ip + "_" + str(port)] = {
                "ip": ip, "port": port, "proto": "tcp"}
            # Will not exit if port was not ssh
            is_ok = len(scan.get("recommendations",{})) == 0
            if not is_ok:
                result.info_updates.append(InfoUpdate(
                    collection="ports",
                    db_key=port_key,
                    infos={"compliant": "False"}
                ))
                result.tag_additions.append(TagAddition(
                    collection="ports",
                    db_key=port_key,
                    tag=Tag(self.getTags()["SSH-flaw"], notes=notes)
                ))
            result.notes = notes
        except KeyError:
            return PluginResult.empty()
        return result
