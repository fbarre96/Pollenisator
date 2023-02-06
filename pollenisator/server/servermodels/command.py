from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.command import Command
from pollenisator.core.controllers.commandcontroller import CommandController
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.core.components.utils import JSONEncoder, JSONDecoder
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
        dbclient = DBClient.getInstance()

        results = dbclient.findInDb(targetdb, "commands", pipeline, True)
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
        dbclient = DBClient.getInstance()
        result = dbclient.findInDb(targetdb, "commands", pipeline, False)
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
    dbclient = DBClient.getInstance()
    results = dbclient.findInDb("pollenisator", "commands", pipeline, True)
    if results is None:
        return []
    return [x for x in results]

def doDelete(pentest, command):
    dbclient = DBClient.getInstance()
    #TODO : delete from checks
    # Remove from all waves this command.
    if command.indb == "pollenisator":
        pentests = dbclient.listPentestNames()
    else:
        pentests = [command.indb]
    for pentest in pentests:
        waves = dbclient.findInDb(pentest, "waves")
        for wave in waves:
            toBeUpdated = wave["wave_commands"]
            if command._id in wave["wave_commands"]:
                toBeUpdated.remove(command._id)
                dbclient.updateInDb(pentest, "waves", {"_id": wave["_id"]}, {
                    "$set": {"wave_commands": toBeUpdated}}, False)
        # Remove all tools refering to this command's name.
        dbclient.deleteFromDb(pentest,
                                   "tools", {"name": command.name}, True, True)


    res = dbclient.deleteFromDb(command.indb, "commands", {
        "_id": ObjectId(command._id)}, False, True)
    if res is None:
        return 0
    else:
        return res.deleted_count

@permission("user")
def deleteCommand(command_iid, **kwargs):
    user = kwargs["token_info"]["sub"]
    dbclient = DBClient.getInstance()
    c = dbclient.findInDb("pollenisator",
        "commands", {"_id": ObjectId(command_iid)}, False)
    if c is None:
        return "Not found", 404
    command = Command(c)

    return doDelete("pollenisator", command)

@permission("pentester")
def delete(pentest, command_iid, **kwargs):
    user = kwargs["token_info"]["sub"]
    dbclient = DBClient.getInstance()
    c = dbclient.findInDb(pentest,
        "commands", {"_id": ObjectId(command_iid)}, False)
    if c is None:
        return "Not found", 404
    command = Command(c)
    return doDelete(pentest, command)
    

def doInsert(pentest, body, user):
    dbclient = DBClient.getInstance()
    existing = dbclient.findInDb(
        body["indb"], "commands", {"name": body["name"]}, False)
    if existing is not None:
        return {"res": False, "iid": existing["_id"]}
    if "_id" in body:
        del body["_id"]
    body["owners"] = [user]
    ins_result = dbclient.insertInDb(
        body["indb"], "commands", body, '', True)
    iid = ins_result.inserted_id
    return {"res": True, "iid": iid}

@permission("pentester")
def insert(pentest, body, **kwargs):
    user = kwargs["token_info"]["sub"]
    return doInsert(pentest, body, user)
   

@permission("pentester")
def update(pentest, command_iid, body, **kwargs):
    dbclient = DBClient.getInstance()
    command = Command(dbclient.findInDb(pentest,
        "commands", {"_id": ObjectId(command_iid)}, False))
    if "owners" in body:
        del body["owners"]
    if "_id" in body:
        del body["_id"]
    dbclient.updateInDb(command.indb, "commands", {"_id": ObjectId(command_iid)}, {"$set": body}, False, True)
    return True

@permission("user")
def addToMyCommands(command_iid, **kwargs):
    """Add a command to the user's commands list."""
    user = kwargs["token_info"]["sub"]
    dbclient = DBClient.getInstance()
    res = dbclient.findInDb("pollenisator", "commands", {
                                 "_id": ObjectId(command_iid)}, False)
    if res is None:
        return "Not found", 404
    dbclient.updateInDb("pollenisator", "commands", {
                                 "_id": ObjectId(command_iid)}, {"$push":{"owners":user}})
    res = "Updated"
    return "OK"

def addUserCommandsToPentest(pentest, user):
    """Add all commands owned by user to pentest database."""
    dbclient = DBClient.getInstance()
    worker = dbclient.findInDb(
        "pollenisator", "workers", {"name": user}, False)
    if worker is not None:
        worker_commands = worker.get("known_commands", [])
        commands = dbclient.findInDb(
            "pollenisator", "commands", {"bin_path": {"$in":worker_commands}}, True)
    else:
        commands = dbclient.findInDb(
            "pollenisator", "commands", {"owners": user}, True)
    for command in commands:
        mycommand = command
        mycommand["original_iid"] = str(command["_id"])
        mycommand["indb"] = pentest
        res = doInsert(pentest, mycommand, user)
        if not res["res"]:
            dbclient.updateInDb(pentest, "commands", {
                                 "_id": ObjectId(res["iid"])}, {"$push":{"owners":user}})
    return True
   
