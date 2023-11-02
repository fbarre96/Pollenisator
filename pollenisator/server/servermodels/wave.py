from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.wave import Wave
from pollenisator.server.servermodels.tool import ServerTool
from pollenisator.server.servermodels.scope import ServerScope
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance, delete as checkinstance_delete
from pollenisator.core.components.utils import JSONEncoder
import json
from pollenisator.server.permission import permission


class ServerWave(Wave, ServerElement):

    command_variables = ["wave"]

    def __init__(self, pentest="", *args, **kwargs):
        super().__init__(*args, **kwargs)
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
            
    @classmethod
    def replaceCommandVariables(cls, pentest, command, data):
        return command.replace("|wave|", data.get("wave", ""))

    def checkAllTriggers(self):
        self.add_wave_checks()

    def add_wave_checks(self):
        self.addChecks(["wave:onAdd"])

    def addChecks(self, lvls):
        """
        Add the appropriate checks (level check and wave's commands check) for this scope.
        """
        # query mongo db commands collection for all commands having lvl == network or domain
        dbclient = DBClient.getInstance()
        search = {"lvl":{"$in": lvls}}
        pentest_type = dbclient.findInDb(self.pentest, "settings", {"key":"pentest_type"}, False)
        if pentest_type is not None:
            search["pentest_types"] = pentest_type["value"]
        # query mongo db commands collection for all commands having lvl == network or domain 
        checkitems = CheckItem.fetchObjects(search)
        if checkitems is None:
            return
        for check in checkitems:
            CheckInstance.createFromCheckItem(self.pentest, check, str(self._id), "wave")

    def getTools(self):
        """Return scope assigned tools as a list of mongo fetched tools dict
        Returns:
            list of defect raw mongo data dictionnaries
        """
        return ServerTool.fetchObjects(self.pentest, {"wave": self.wave, "lvl": {"$in": self.getTriggers()}})

    def removeAllTool(self, command_name):
        """
        Remove from every member of this wave the old tool corresponding to given command name but only if the tool is not done.
        We preserve history

        Args:
            command_name: The command that we want to remove all the tools.
        """
        dbclient = DBClient.getInstance()
        tools = ServerTool.fetchObjects(self.pentest, {"name": command_name, "wave": self.wave})
        for tool in tools:
            if "done" not in tool.getStatus():
                tool.delete()

    @classmethod
    def getTriggers(cls):
        """
        Return the list of trigger declared here
        """
        return ["wave:onAdd"]

@permission("pentester")
def delete(pentest, wave_iid):
    dbclient = DBClient.getInstance()
    wave_o = ServerWave(pentest, dbclient.findInDb(pentest, "waves", {"_id": ObjectId(wave_iid)}, False))
    dbclient.deleteFromDb(pentest, "tools", {"wave": wave_o.wave}, True)
    dbclient.deleteFromDb(pentest, "intervals", {"wave": wave_o.wave}, True)
    checks = dbclient.findInDb(pentest, "cheatsheet",
                                {"target_iid": str(wave_iid)}, True)
    for check in checks:
        checkinstance_delete(pentest, check["_id"])
    res = dbclient.deleteFromDb(pentest, "waves", {"_id": ObjectId(wave_iid)}, False)
    
    if res is None:
        return 0
    else:
        return res
    
@permission("pentester")
def insert(pentest, body):
    dbclient = DBClient.getInstance()
    wave_o = ServerWave(pentest, body)
    # Checking unicity
    existing = dbclient.findInDb(pentest, "waves", {"wave": wave_o.wave}, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    # Inserting scope
    res_insert = dbclient.insertInDb(pentest, "waves", {"wave": wave_o.wave, "wave_commands": list(wave_o.wave_commands)})
    ret = res_insert.inserted_id
    wave_o._id = ret
    wave_o.add_wave_checks()
    return {"res":True, "iid":ret}

@permission("pentester")
def update(pentest, wave_iid, body):
    dbclient = DBClient.getInstance()
    oldWave_o = ServerWave(pentest, dbclient.findInDb(pentest, "waves", {"_id":ObjectId(wave_iid)}, False))
    oldCommands = oldWave_o.wave_commands
    wave_commands = body["wave_commands"]
    dbclient.updateInDb(pentest, "waves", {"_id":ObjectId(wave_iid)}, {"$set":body}, False, True)
    

def addUserCommandsToWave(pentest, wave_iid, user):
    dbclient = DBClient.getInstance()
    
    mycommands = dbclient.findInDb(pentest, "commands", {"owners":user}, True)
    comms = [command["_id"] for command in mycommands]
    wave = dbclient.findInDb(pentest, "waves", {"_id":ObjectId(wave_iid)}, False)
    if wave is None:
        return False
    wave["wave_commands"] += comms
    update(pentest, wave_iid, {"wave_commands": wave["wave_commands"]})
    return True

