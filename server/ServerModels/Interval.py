from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Models.Interval import Interval
from server.ServerModels.Tool import ServerTool
from core.Components.Utils import JSONEncoder
import json

mongoInstance = MongoCalendar.getInstance()

class ServerInterval(Interval):

    def __init__(self, pentest, *args, **kwargs):
        self.pentest = pentest
        super().__init__(*args, **kwargs)

    def setToolsInTime(self):
        """Get all OOT (Out of Time) tools in this wave and checks if this Interval makes them in time. 
        If it is the case, set them in time.
        """
        if Utils.fitNowTime(self.dated, self.datef):
            tools = ServerTool.fetchObjects(self.pentest, {"wave": self.wave, "status": "OOT"})
            for tool in tools:
                tool.setInTime()

def delete(pentest, interval_iid):
    mongoInstance.connectToDb(pentest)
    interval_o = ServerInterval(pentest, mongoInstance.find("intervals", {"_id": ObjectId(interval_iid)}, False))
    res = mongoInstance.delete("intervals", {"_id": ObjectId(interval_iid)}, False)
    parent_wave = mongoInstance.find("waves", {"wave": interval_o.wave}, False)
    if parent_wave is not None:
        mongoInstance.notify(pentest,
                                "waves", parent_wave["_id"], "update", "")
        other_intervals = mongoInstance.find("waves", {"wave": interval_o.wave})
        no_interval_in_time = True
        for other_interval in other_intervals:
            other_interval = ServerInterval(pentest, other_interval)
            if Utils.fitNowTime(other_interval.dated, other_interval.datef):
                no_interval_in_time = False
                break
        if no_interval_in_time:
            tools = mongoInstance.find("tools", {"wave": interval_o.wave})
            for tool in tools:
                tool = ServerTool(pentest, tool)
                tool.setOutOfTime(pentest)
    if res is None:
        return 0
    else:
        return res.deleted_count

def insert(pentest, data):
    mongoInstance.connectToDb(pentest)
    interval_o = ServerInterval(pentest, data)
    parent = interval_o.getParentId()
    ins_result = mongoInstance.insert("intervals", data, parent)
    interval_o.setToolsInTime()
    iid = ins_result.inserted_id
    return {"res":True, "iid":iid}


def update(pentest, interval_iid, data):
    mongoInstance.connectToDb(pentest)
    interval_o = ServerInterval(pentest, mongoInstance.find("intervals", {"_id": ObjectId(interval_iid)}, False))
    interval_o.setToolsInTime()
    return mongoInstance.update("intervals", {"_id":ObjectId(interval_iid)}, {"$set":data}, False, True)