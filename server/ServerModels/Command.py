from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Models.Command import Command
from server.ServerModels.Element import ServerElement
from core.Components.Utils import JSONEncoder
import json

mongoInstance = MongoCalendar.getInstance()

class ServerCommand(Command):

    def __init__(self, pentest, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pentest = pentest

    @classmethod
    def fetchObjects(cls, pipeline, targetdb="pollenisator"):
        """Fetch many commands from database and return a Cursor to iterate over Command objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on Command objects
        """
        mongoInstance.connectToDb(targetdb)
        results = mongoInstance.findInDb(targetdb, "commands", pipeline, True)
        if results is None:
            return None
        for result in results:
            yield(ServerCommand(targetdb, result))
    
    @classmethod
    def fetchObject(cls, pipeline, targetdb="pollenisator"):
        """Fetch one command from database and return a ServerCommand object
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a Server Command
        """
        mongoInstance.connectToDb(targetdb)
        result = mongoInstance.findInDb(targetdb, "commands", pipeline, False)
        if result is None:
            return None
        return ServerCommand(targetdb, result)

def delete(pentest, command_iid):
    mongoInstance.connectToDb(pentest)
    command = Command(mongoInstance.find("commands", {"_id":command_iid}))
    mongoInstance.updateInDb(command.indb, "group_commands", {}, {
        "$pull": {"commands": command.name}}, True, True)
    # Remove from all waves this command.
    if command.indb == "pollenisator":
        calendars = mongoInstance.getPentestList()
    else:
        calendars = [command.indb]
    for calendar in calendars:
        waves = mongoInstance.findInDb(calendar, "waves")
        for wave in waves:
            toBeUpdated = wave["wave_commands"]
            if command.name in wave["wave_commands"]:
                toBeUpdated.remove(command.name)
                mongoInstance.updateInDb(calendar, "waves", {"_id": wave["_id"]}, {
                    "$set": {"wave_commands": toBeUpdated}}, False)
        # Remove all tools refering to this command's name.
        mongoInstance.deleteFromDb(calendar,
                                "tools", {"name": command.name}, True, True)
    res = mongoInstance.deleteFromDb(command.indb, "commands", {
                                   "_id": command_iid}, False, True)
    if res is None:
        return 0
    else:
        return res.deleted_count

def insert(pentest, data):
    existing = mongoInstance.findInDb(
            data["indb"], "commands", {"name": data["name"]}, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in data:
        del data["_id"]
    ins_result = mongoInstance.insertInDb(data["indb"], "commands", data, '', True)
    iid = ins_result.inserted_id
    return {"res":True, "iid":iid}

def update(pentest, command_iid, data):
    return mongoInstance.updateInDb(data["indb"], "commands", {"_id":ObjectId(command_iid)}, {"$set":data}, False, True)