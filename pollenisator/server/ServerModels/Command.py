from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Models.Command import Command
from pollenisator.server.ServerModels.Element import ServerElement
from pollenisator.core.Components.Utils import JSONEncoder
from pollenisator.server.permission import permission
import json


class ServerCommand(Command, ServerElement):

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
        mongoInstance = MongoCalendar.getInstance()

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
        mongoInstance = MongoCalendar.getInstance()
        mongoInstance.connectToDb(targetdb)
        result = mongoInstance.findInDb(targetdb, "commands", pipeline, False)
        if result is None:
            return None
        return ServerCommand(targetdb, result)

    @classmethod
    def getList(cls, pipeline=None, targetdb="pollenisator"):
        """
        Get all command's name registered on database
        Args:
            pipeline: default to None. Condition for mongo search.
        Returns:
            Returns the list of commands name found inside the database. List may be empty.
        """
        if pipeline is None:
            pipeline = {}
        return [command.name for command in cls.fetchObjects(pipeline, targetdb)]

@permission("pentester")
def delete(pentest, command_iid):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    command = Command(mongoInstance.find("commands", {"_id":ObjectId(command_iid)}, False))
    mongoInstance.updateInDb(command.indb, "group_commands", {}, {
        "$pull": {"commands": command.name}}, True, True)
    # Remove from all waves this command.
    if command.indb == "pollenisator":
        calendars = mongoInstance.listCalendars()
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

    print(f'deleting from {command.indb} id {str(command_iid)}')
    res = mongoInstance.deleteFromDb(command.indb, "commands", {
                                   "_id": ObjectId(command_iid)}, False, True)
    if res is None:
        return 0
    else:
        return res.deleted_count

@permission("pentester")
def insert(pentest, body):
    mongoInstance = MongoCalendar.getInstance()
    existing = mongoInstance.findInDb(
            body["indb"], "commands", {"name": body["name"]}, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    ins_result = mongoInstance.insertInDb(body["indb"], "commands", body, '', True)
    iid = ins_result.inserted_id
    return {"res":True, "iid":iid}
    
@permission("pentester")
def update(pentest, command_iid, body):
    mongoInstance = MongoCalendar.getInstance()
    return mongoInstance.updateInDb(body["indb"], "commands", {"_id":ObjectId(command_iid)}, {"$set":body}, False, True)
