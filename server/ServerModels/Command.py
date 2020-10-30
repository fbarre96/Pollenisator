from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Models.Command import Command
from core.Components.Utils import JSONEncoder
import json

mongoInstance = MongoCalendar.getInstance()


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
    ins_result = mongoInstance.insertInDb(data["indb"], "commands", data, '', True)
    iid = ins_result
    return {"res":True, "iid":iid}

def update(pentest, command_iid, data):
    return mongoInstance.updateInDb(data["indb"], "commands", {"_id":ObjectId(command_iid)}, {"$set":data}, False, True)
