from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Models.CommandGroup import CommandGroup
from pollenisator.core.Components.Utils import JSONEncoder, JSONDecoder
from pollenisator.server.permission import permission
import json

class ServerCommandGroup(CommandGroup):

    def __init__(self, pentest, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pentest = pentest

    @classmethod
    def fetchObjects(cls, pipeline, targetdb="pollenisator"):
        """Fetch many commands from database and return a Cursor to iterate over Command Group objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on Command Group objects
        """
        mongoInstance = MongoCalendar.getInstance()
        mongoInstance.connectToDb(targetdb)
        results = mongoInstance.findInDb(targetdb, "group_commands", pipeline, True)
        if results is None:
            return None
        for result in results:
            yield(ServerCommandGroup(targetdb, result))

@permission("user")
def deleteCommandGroup(command_group_iid, **kwargs):
    user = kwargs["token_info"]["sub"]
    mongoInstance = MongoCalendar.getInstance()
    group = mongoInstance.findInDb("pollenisator", "group_commands", {"_id": ObjectId(command_group_iid)}, False)
    if group is None:
        return "Not found", 404
    if group["owner"] != "Worker":
        if group["owner"] != user and group["owner"] != "":
            return "Forbidden", 403
    return doDelete("pollenisator", group)

@permission("pentester")
def delete(pentest, command_group_iid, **kwargs):
    user = kwargs["token_info"]["sub"]
    mongoInstance = MongoCalendar.getInstance()
    group = mongoInstance.findInDb(pentest, "group_commands", {"_id": ObjectId(command_group_iid)}, False)
    if group is None:
        return "Not found", 404
    if group["owner"] != "Worker":
        if group["owner"] != user and group["owner"] != "":
            return "Forbidden", 403
    return doDelete(pentest, group)

def doDelete(pentest, group):
    mongoInstance = MongoCalendar.getInstance()
    res = mongoInstance.deleteFromDb(pentest, "group_commands", {
                                   "_id": ObjectId(group["_id"])}, False, True)
    if res is None:
        return 0
    else:
        return res.deleted_count


def doInsert(pentest, body, user):
    mongoInstance = MongoCalendar.getInstance()
    if "_id" in body:
        del body["_id"]
    existing = mongoInstance.findInDb(
            body.get("indb", "pollenisator"), "group_commands", {"name": body["name"], "owner":user}, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    body["owner"] = user
    ins_result = mongoInstance.insertInDb(body.get("indb", "pollenisator"), "group_commands", body, '', True)
    iid = ins_result.inserted_id
    return {"res":True, "iid":iid}


@permission("pentester")
def insert(pentest, body, **kwargs):
    user = kwargs["token_info"]["sub"]
    if body.get("owner", "") == "Worker":
        return doInsert(pentest, body, "Worker")
    return doInsert(pentest, body, user)
    

@permission("user")
def getCommandGroups(body):
    pipeline = body.get("pipeline", {})
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    mongoInstance = MongoCalendar.getInstance()
    results = mongoInstance.findInDb("pollenisator", "group_commands", pipeline, True)
    if results is None:
        return []
    return [x for x in results]

@permission("pentester")
def update(pentest, command_group_iid, body, **kwargs):
    user = kwargs["token_info"]["sub"] if body.get("owner", "") != "Worker" else "Worker"
    mongoInstance = MongoCalendar.getInstance()
    group = CommandGroup(mongoInstance.find(
        "group_commands", {"_id": ObjectId(command_group_iid)}, False))
    if group.owner != user  and group.owner != "" and group.owner != "Worker":
        return "Forbidden", 403
    if "owner" in body:
        del body["owner"]
    if "_id" in body:
        del body["_id"]
    if "name" in body:
        del body["name"]
    res = mongoInstance.updateInDb(body["indb"], "group_commands", {"_id":ObjectId(command_group_iid), "owner":user}, {"$set":body}, False, True)
    return True

def addUserGroupCommandsToPentest(pentest, user):
    mongoInstance = MongoCalendar.getInstance()
    mygroupcommands = mongoInstance.findInDb(
        "pollenisator", "group_commands", {"owner": user}, True)
    for gr in mygroupcommands:
        mygr = gr
        new_comms = []
        for original_comm_id in gr["commands"]:
            if "ObjectId|" in str(original_comm_id):
                original_comm_id = original_comm_id.replace("ObjectId|", "")
            original_comm = mongoInstance.findInDb(
                "pollenisator", "commands", {"_id":ObjectId(original_comm_id)}, False)
            if original_comm:
                copied_comm = mongoInstance.findInDb(
                    pentest, "commands", {"name":original_comm["name"], "owner":original_comm["owner"]}, False)
                new_comms.append(str(copied_comm["_id"]))
        mygr["commands"] = new_comms
        mygr["indb"] = pentest
        res = doInsert(pentest, mygr, user)
    return True
