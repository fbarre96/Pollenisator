"""A plugin to parse a bloodhound-ce scan """
from typing import IO, Any, Dict, List, Optional, Tuple
from pollenisator.core.components.tag import Tag
from pollenisator.plugins.plugin import Plugin
from pollenisator.plugins.plugin_result import PluginResult
from pollenisator.core.models.ip import Ip
from pollenisator.server.modules.activedirectory.users import User
from pollenisator.server.modules.activedirectory.computers import Computer
from pollenisator.core.components.utils import performLookUp
from zipfile import ZipFile
from io import BytesIO
import json

def parse_users(open_file):
    try:
        data = json.loads(open_file.read())
    except:
        return None
    if "meta" not in data or not "data" in data:
        return None
    data = data["data"]
    users = []
    for user in data:
        props = user.get("Properties", None)
        if props is None:
            continue
        name = props.get("name", None)
        domain = props.get("domain", None)
        desc = props.get("description", None)
        enabled = props.get("enabled", False)
        if name is None or domain is None or not enabled:
            continue
        if "@" in name:
            name = name.split("@")[0]
        users.append({"name":name.lower(), "domain":domain.lower(), "desc":desc})
    return users


def parse_computers(open_file):
    try:
        data = json.loads(open_file.read())
    except:
        return None
    if "meta" not in data or "data" not in data:
        return None
    data = data["data"]
    computers = []
    for computer in data:
        props = computer.get("Properties", None)
        if props is None:
            continue
        is_deleted = computer.get("IsDeleted", False)
        if is_deleted:
            continue
        name = props.get("name", None)
        domain = props.get("domain", None)
        enabled = props.get("enabled", False)
        if name is None or domain is None or not enabled:
            continue
        if name.endswith(domain):
            name = name[:len(domain)+1] # name+ . + domain
        ip = performLookUp(name+"."+domain)
        if ip is not None:
            computers.append({"name":name.lower(), "domain":domain.lower(), "ip":ip})
    return computers


def collectBloodHoundCEResults(pentest, users, computers, result):
    """Collect BloodHoundCE results into a PluginResult."""
    inserted_user = 0
    inserted_computer = 0
    for computer in computers:
        result.ips.append(Ip(pentest).initialize(str(computer["ip"]), infos={"plugin": BloodHoundCE.get_name()}))
        comp_m = Computer(pentest).initialize(computer["name"], computer["ip"], computer["domain"], infos={"plugin": BloodHoundCE.get_name()})
        result.computers.append(comp_m)
        inserted_computer += 1
    for user in users:
        domain = user.get("domain", "")
        username = user.get("name", "")
        password = ""
        user_m = User(pentest).initialize(domain, username, password, None, user.get("desc"), infos={"plugin": BloodHoundCE.get_name()})
        result.users.append(user_m)
        inserted_user += 1
    return inserted_user, inserted_computer



class BloodHoundCE(Plugin):
    """Inherits Plugin
    """
    default_bin_names = ["bloodhound-python-ce", "bloodhound-ce.py"]

    def changeCommand(self, command, outputDir, toolname):
        """
        Summary: Complete the given command with the tool output file option and filename absolute path.
        Args:
            * command : the command line to complete
            * outputDir : the directory where the output file must be generated
            * toolname : the tool name (to be included in the output file name)
        Return:
            The command completed with the tool output file option and filename absolute path.
        """
        # zip all
        if "--zip" not in command:
            command += "  --zip "
        string= command+" && find . -name '*bloodhound.zip' -exec mv {} "+outputDir+toolname+" \\;"
        return string


    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".zip"

    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " {} "

    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        return commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0]

    def getTags(self):
        """Returns the tags possibly returned by this plugin
        Returns:
            list of Tag
        """
        return {}


    def Parse(self, pentest: str, file_opened: IO[bytes], **kwargs: Dict[str, Any]) -> PluginResult:
        """
        Parse an opened file to extract information.

        Args:
            pentest (str): The name of the pentest.
            file_opened (BinaryIO): The opened file.
            **kwargs ([str, Any]): Additional parameters (not used).

        Returns:
            PluginResult with collected objects.
        """
        if str(kwargs.get("ext", "")).lower() != self.getFileOutputExt():
            return PluginResult.empty()
        path = kwargs.get("filename")
        if path is None:
            return PluginResult.empty()
        try:
            myzip = ZipFile(BytesIO(file_opened.read()))
        except:
            return PluginResult.empty()
        files = myzip.namelist()
        users = []
        computers = []
        for file in files:
            if file.endswith("_users.json"):
                f = myzip.open(file)
                users = parse_users(f)
                f.close()
                if users is None:
                    return PluginResult.empty()
            if file.endswith("_computers.json"):
                f = myzip.open(file)
                computers = parse_computers(f)
                f.close()
                if computers is None:
                    return PluginResult.empty()
        result = PluginResult(notes="", tags=[], lvl="wave", targets={"wave": None})
        inserted_user, inserted_computer = collectBloodHoundCEResults(pentest, users, computers, result)
        result.notes = "found users : " + str(inserted_user)
        result.notes += "\nfound computers : " + str(inserted_computer)
        myzip.close()
        return result