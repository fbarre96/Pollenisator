from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Models.Command import Command
from pollenisator.core.Controllers.CommandController import CommandController
from pollenisator.server.ServerModels.Element import ServerElement
from pollenisator.core.Components.Utils import JSONEncoder, JSONDecoder
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
        return [command._id for command in cls.fetchObjects(pipeline, targetdb)]

@permission("user")
def getCommands(body):
    pipeline = body.get("pipeline", {})
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    mongoInstance = MongoCalendar.getInstance()
    results = mongoInstance.findInDb("pollenisator", "commands", pipeline, True)
    if results is None:
        return []
    return [x for x in results]

def doDelete(pentest, command):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    mongoInstance.updateInDb("pollenisator", "group_commands", {"owner": command.owner}, {
        "$pull": {"commands": command._id}}, True, True)
    # Remove from all waves this command.
    if command.indb == "pollenisator":
        calendars = mongoInstance.listCalendarNames()
    else:
        calendars = [command.indb]
    for calendar in calendars:
        waves = mongoInstance.findInDb(calendar, "waves")
        for wave in waves:
            toBeUpdated = wave["wave_commands"]
            if command._id in wave["wave_commands"]:
                toBeUpdated.remove(command._id)
                mongoInstance.updateInDb(calendar, "waves", {"_id": wave["_id"]}, {
                    "$set": {"wave_commands": toBeUpdated}}, False)
        # Remove all tools refering to this command's name.
        mongoInstance.deleteFromDb(calendar,
                                   "tools", {"name": command.name}, True, True)

    res = mongoInstance.deleteFromDb(command.indb, "commands", {
        "_id": ObjectId(command._id)}, False, True)
    if res is None:
        return 0
    else:
        return res.deleted_count

@permission("user")
def deleteCommand(command_iid, **kwargs):
    user = kwargs["token_info"]["sub"]
    mongoInstance = MongoCalendar.getInstance()
    c = mongoInstance.findInDb("pollenisator",
        "commands", {"_id": ObjectId(command_iid)}, False)
    if c is None:
        return "Not found", 404
    command = Command(c)
    if command.owner != user and command.owner != "" and command.owner != "Worker":
        return "Forbidden", 403
    return doDelete("pollenisator", command)

@permission("pentester")
def delete(pentest, command_iid, **kwargs):
    user = kwargs["token_info"]["sub"]
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    c = mongoInstance.find(
        "commands", {"_id": ObjectId(command_iid)}, False)
    if c is None:
        return "Not found", 404
    command = Command(c)
    if command.owner != "Worker":
        if command.owner != user and command.owner != "":
            return "Forbidden", 403
    return doDelete(pentest, command)
    

def doInsert(pentest, body, user):
    mongoInstance = MongoCalendar.getInstance()
    existing = mongoInstance.findInDb(
        body["indb"], "commands", {"owner": user, "name": body["name"]}, False)
    if existing is not None:
        return {"res": False, "iid": existing["_id"]}
    if "_id" in body:
        del body["_id"]
    body["owner"] = user
    ins_result = mongoInstance.insertInDb(
        body["indb"], "commands", body, '', True)
    iid = ins_result.inserted_id
    return {"res": True, "iid": iid}

@permission("pentester")
def insert(pentest, body, **kwargs):
    user = kwargs["token_info"]["sub"]
    if body.get("owner", "") == "Worker":
        return doInsert(pentest, body, "Worker")
    return doInsert(pentest, body, user)
   

@permission("pentester")
def update(pentest, command_iid, body, **kwargs):
    user = kwargs["token_info"]["sub"] if body.get("owner", "") != "Worker" else "Worker"
    mongoInstance = MongoCalendar.getInstance()
    command = Command(mongoInstance.find(
        "commands", {"_id": ObjectId(command_iid)}, False))
    if command.owner != user  and command.owner != "" and command.owner != "Worker":
        return "Forbidden", 403
    if "owner" in body:
        del body["owner"]
    if "_id" in body:
        del body["_id"]
    mongoInstance.updateInDb(command.indb, "commands", {"_id": ObjectId(command_iid)}, {"$set": body}, False, True)
    return True

@permission("user")
def addToMyCommands(command_iid, **kwargs):
    user = kwargs["token_info"]["sub"]
    mongoInstance = MongoCalendar.getInstance()
    res = mongoInstance.findInDb("pollenisator", "commands", {
                                 "_id": ObjectId(command_iid)}, False)
    if res is None:
        return False
    res["owner"] = user
    res["indb"] = "pollenisator"
    return doInsert("pollenisator", res, user)

@permission("user")
def addToWorkerCommands(command_iid, **kwargs):
    user = kwargs["token_info"]["sub"]
    mongoInstance = MongoCalendar.getInstance()
    res = mongoInstance.findInDb("pollenisator", "commands", {
                                 "_id": ObjectId(command_iid)}, False)
    if res is None:
        return False
    res["owner"] = "Worker"
    res["indb"] = "pollenisator"
    return doInsert("pollenisator", res, "Worker")


def addUserCommandsToPentest(pentest, user):
    mongoInstance = MongoCalendar.getInstance()
    mycommands = mongoInstance.findInDb(
        "pollenisator", "commands", {"owner": user}, True)
    for command in mycommands:
        mycommand = command
        mycommand["indb"] = pentest
        res = doInsert(pentest, mycommand, user)
    return True
