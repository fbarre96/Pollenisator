from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Models.CommandGroup import CommandGroup
from core.Components.Utils import JSONEncoder
import json

mongoInstance = MongoCalendar.getInstance()

def delete(pentest, command_group_iid):
    res = mongoInstance.deleteFromDb("pollenisator", "group_commands", {
                                   "_id": ObjectId(command_group_iid)}, False, True)
    if res is None:
        return 0
    else:
        return res.deleted_count

def insert(pentest, data):
    existing = mongoInstance.findInDb(
            "pollenisator", "group_commands", {"name": data["name"]}, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    ins_result = mongoInstance.insertInDb("pollenisator", "group_commands", data, '', True)
    iid = ins_result.inserted_id
    return {"res":True, "iid":iid}

def update(pentest, command_group_iid, data):
    return mongoInstance.updateInDb("pollenisator", "group_commands", {"_id":ObjectId(command_group_iid)}, {"$set":data}, False, True)