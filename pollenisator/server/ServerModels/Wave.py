from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Models.Wave import Wave
from pollenisator.server.ServerModels.Tool import ServerTool
from pollenisator.server.ServerModels.Scope import ServerScope
from pollenisator.server.ServerModels.Element import ServerElement
from pollenisator.server.modules.Cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.Cheatsheet.checkinstance import CheckInstance, delete as checkinstance_delete
from pollenisator.core.Components.Utils import JSONEncoder
import json
from pollenisator.server.permission import permission


class ServerWave(Wave, ServerElement):

    def __init__(self, pentest="", *args, **kwargs):
        super().__init__(*args, **kwargs)
        mongoInstance = MongoCalendar.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")


    def addAllChecks(self):
        """
        Add the appropriate checks (level check and wave's commands check) for this scope.
        """
        # query mongo db commands collection for all commands having lvl == network or domain
        checkitems = CheckItem.fetchObjects({"lvl": {"$in": ["wave"]}})
        if checkitems is None:
            return
        for check in checkitems:
            CheckInstance.createFromCheckItem(self.pentest, check, str(self._id), "waves")

    def removeAllTool(self, command_name):
        """
        Remove from every member of this wave the old tool corresponding to given command name but only if the tool is not done.
        We preserve history

        Args:
            command_name: The command that we want to remove all the tools.
        """
        mongoInstance = MongoCalendar.getInstance()
        tools = ServerTool.fetchObjects(self.pentest, {"name": command_name, "wave": self.wave})
        for tool in tools:
            if "done" not in tool.getStatus():
                tool.delete()

@permission("pentester")
def delete(pentest, wave_iid):
    mongoInstance = MongoCalendar.getInstance()
    wave_o = ServerWave(pentest, mongoInstance.findInDb(pentest, "waves", {"_id": ObjectId(wave_iid)}, False))
    mongoInstance.deleteFromDb(pentest, "tools", {"wave": wave_o.wave}, True)
    mongoInstance.deleteFromDb(pentest, "intervals", {"wave": wave_o.wave}, True)
    checks = mongoInstance.findInDb(pentest, "cheatsheet",
                                {"target_iid": str(wave_iid)}, True)
    for check in checks:
        checkinstance_delete(pentest, check["_id"])
    res = mongoInstance.deleteFromDb(pentest, "waves", {"_id": ObjectId(wave_iid)}, False)
    
    if res is None:
        return 0
    else:
        return res.deleted_count
    
@permission("pentester")
def insert(pentest, body):
    mongoInstance = MongoCalendar.getInstance()
    wave_o = ServerWave(pentest, body)
    # Checking unicity
    existing = mongoInstance.findInDb(pentest, "waves", {"wave": wave_o.wave}, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    # Inserting scope
    res_insert = mongoInstance.insertInDb(pentest, "waves", {"wave": wave_o.wave, "wave_commands": list(wave_o.wave_commands)})
    ret = res_insert.inserted_id
    wave_o._id = ret
    wave_o.addAllChecks()
    return {"res":True, "iid":ret}

@permission("pentester")
def update(pentest, wave_iid, body):
    mongoInstance = MongoCalendar.getInstance()
    oldWave_o = ServerWave(pentest, mongoInstance.findInDb(pentest, "waves", {"_id":ObjectId(wave_iid)}, False))
    oldCommands = oldWave_o.wave_commands
    wave_commands = body["wave_commands"]
    mongoInstance.updateInDb(pentest, "waves", {"_id":ObjectId(wave_iid)}, {"$set":body}, False, True)
    

def addUserCommandsToWave(pentest, wave_iid, user):
    mongoInstance = MongoCalendar.getInstance()
    
    mycommands = mongoInstance.findInDb(pentest, "commands", {"owners":user}, True)
    comms = [command["_id"] for command in mycommands]
    wave = mongoInstance.findInDb(pentest, "waves", {"_id":ObjectId(wave_iid)}, False)
    if wave is None:
        return False
    wave["wave_commands"] += comms
    update(pentest, wave_iid, {"wave_commands": wave["wave_commands"]})
    return True

