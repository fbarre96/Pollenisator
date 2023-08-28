"""A plugin to parse a bloodhound scan """
from pollenisator.plugins.plugin import Plugin
from pollenisator.server.servermodels.ip import ServerIp
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


def updateDatabase(pentest, users, computers):
    # Check if any ip has been found.
    inserted_user = 0
    inserted_computer = 0
    for computer in computers:
        ip_m = ServerIp(pentest).initialize(str(computer["ip"]), infos={"plugin":BloodHound.get_name()})
        insert_ret = ip_m.addInDb()
        comp_m = Computer(pentest).initialize(pentest, None, computer["name"], computer["ip"], computer["domain"], infos={"plugin":BloodHound.get_name()})
        comp_m.addInDb()
        inserted_computer += 1
    for user in users:
        domain = user.get("domain", "")
        username = user.get("name", "")
        password = ""
        user_m = User(pentest).initialize(pentest, None, domain, username, password, None, user.get("desc"), infos={"plugin":BloodHound.get_name()})
        user_m.addInDb()
        inserted_user += 1
    return inserted_user, inserted_computer



class BloodHound(Plugin):
    """Inherits Plugin
    """
    default_bin_names = ["bloodhound-python", "bloodhound.py"]

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
        return command+" && find . -name '*bloodhound.zip' -exec mv {} "+outputDir+toolname+" \\;"


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


    def Parse(self, pentest, file_opened, **kwargs):
        """
        Parse a opened file to extract information
        Example file:
      
        Args:
            file_opened: the open file
            kwargs: port("") and proto("") are valid
        Returns:
            a tuple with 4 values (All set to None if Parsing wrong file): 
                0. notes: notes to be inserted in tool giving direct info to pentester
                1. tags: a list of tags to be added to tool 
                2. lvl: the level of the command executed to assign to given targets
                3. targets: a list of composed keys allowing retrieve/insert from/into database targerted objects.
        """
        if kwargs.get("ext", "").lower() != self.getFileOutputExt():
            return None, None, None, None
        path = kwargs.get("filename")
        if path is None:
            return None, None, None, None
        try:
            myzip = ZipFile(BytesIO(file_opened.read()))
        except:
            return None, None, None, None
        files = myzip.namelist()
        for file in files:
            if file.endswith("_users.json"):
                f = myzip.open(file)
                users = parse_users(f)
                f.close()
                if users is None:
                    return None,None,None,None
            if file.endswith("_computers.json"):
                f = myzip.open(file)
                computers = parse_computers(f)
                f.close()
                if computers is None:
                    return None,None,None,None
        inserted_user, inserted_computer = updateDatabase(pentest, users, computers)
        notes = "inserted users : "+str(inserted_user)
        notes += "\ninserted computers : "+str(inserted_computer)
        myzip.close()
        return notes, [], "wave", {"wave": None}