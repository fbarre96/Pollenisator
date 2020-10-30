from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Models.Wave import Wave
from server.ServerModels.Tool import ServerTool
from server.ServerModels.Scope import ServerScope
from core.Components.Utils import JSONEncoder
import json

mongoInstance = MongoCalendar.getInstance()

class ServerWave(Wave):

    def __init__(self, pentest, *args, **kwargs):
        self.pentest = pentest
        super().__init__(*args, **kwargs)

    def addAllTool(self, command_name):
        """
        Kind of recursive operation as it will call the same function in its children ports.
        Add the appropriate tools (level check and wave's commands check) for this wave.
        Also add for all registered scopes the appropriate tools.
        Args:
            command_name: The command that we want to create all the tools for.
        """
        mongoInstance.connectToDb(self.pentest)
        command = mongoInstance.findInDb(self.pentest, "commands", {
                                         "name": command_name}, False)
        if command["lvl"] == "wave":
            newTool = ServerTool(self.pentest)
            newTool.initialize(command_name, self.wave, "", "", "", "", "wave")
            newTool.addInDb()
            return
        scopes = mongoInstance.find("scopes", {"wave": self.wave})
        for scope in scopes:
            h = ServerScope(self.pentest, scope)
            h.addAllTool(command_name)

    def removeAllTool(self, command_name):
        """
        Remove from every member of this wave the old tool corresponding to given command name but only if the tool is not done.
        We preserve history

        Args:
            command_name: The command that we want to remove all the tools.
        """
        mongoInstance.connectToDb(self.pentest)
        tools = ServerTool.fetchObjects(self.pentest, {"name": command_name, "wave": self.wave})
        for tool in tools:
            if "done" not in tool.getStatus():
                tool.delete()

def delete(pentest, wave_iid):
    mongoInstance.connectToDb(pentest)
    wave_o = ServerWave(pentest, mongoInstance.find("waves", {"_id": ObjectId(wave_iid)}, False))
    mongoInstance.delete("tools", {"wave": wave_o.wave}, True)
    mongoInstance.delete("intervals", {"wave": wave_o.wave}, True)
    res = mongoInstance.delete("waves", {"_id": ObjectId(wave_iid)}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count

def insert(pentest, data):
    mongoInstance.connectToDb(pentest)
    wave_o = ServerWave(pentest, data)
    # Checking unicity
    existing = mongoInstance.find("waves", {"wave": wave_o.wave}, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    # Inserting scope
    res_insert = mongoInstance.insert("waves", {"wave": self.wave, "wave_commands": list(self.wave_commands)})
    ret = res_insert.inserted_id
    wave_o._id = ret
    for commName in wave_o.wave_commands:
            wave_o.addAllTool(commName)
    return {"res":True, "iid":ret}


def update(pentest, wave_iid, data):
    mongoInstance.connectToDb(pentest)
    oldWave_o = ServerWave(pentest, mongoInstance.find("waves", {"_id":ObjectId(wave_iid)}, False))
    oldCommands = oldWave_o.wave_commands
    wave_commands = data["wave_commands"]
    mongoInstance.update("waves", {"_id":ObjectId(wave_iid)}, {"$set":data}, False, True)
    # If the wave_commands are changed, we have to add and delete corresponding tools.
    for command_name in oldCommands:
        # The previously present command name is not authorized anymore.
        if command_name not in wave_commands:
            # So delete all of its tool (only if not done) from this wave
            oldWave_o.removeAllTool(command_name)
    for command_name in wave_commands:
        # The command authorized is not found, we have to add its new tools.
        if command_name not in oldCommands:
            # So add all of this command's tool to this wave.
            oldWave_o.addAllTool(command_name)