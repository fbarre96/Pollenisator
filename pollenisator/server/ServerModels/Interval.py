from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Models.Interval import Interval
from pollenisator.server.ServerModels.Tool import ServerTool
from pollenisator.server.ServerModels.Element import ServerElement
from pollenisator.core.Components.Utils import JSONEncoder, fitNowTime
import json
from pollenisator.server.permission import permission

class ServerInterval(Interval, ServerElement):

    def __init__(self, pentest="", *args, **kwargs):
        super().__init__(*args, **kwargs)
        mongoInstance = MongoCalendar.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
            
    def setToolsInTime(self):
        """Get all OOT (Out of Time) tools in this wave and checks if this Interval makes them in time. 
        If it is the case, set them in time.
        """
        if fitNowTime(self.dated, self.datef):
            tools = ServerTool.fetchObjects(self.pentest, {"wave": self.wave, "status": "OOT"})
            for tool in tools:
                tool.setInTime()
    
    def getParentId(self):
        """
        Return the mongo ObjectId _id of the first parent of this object. For an interval it is the wave.

        Returns:
            Returns the parent wave's ObjectId _id".
        """
        mongoInstance = MongoCalendar.getInstance()
        return mongoInstance.findInDb(self.pentest, "waves", {"wave": self.wave}, False)["_id"]

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        mongoInstance = MongoCalendar.getInstance()

        ds = mongoInstance.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            # disabling this error as it is an abstract function
            yield cls(pentest, d)  #  pylint: disable=no-value-for-parameter

@permission("pentester")
def delete(pentest, interval_iid):
    mongoInstance = MongoCalendar.getInstance()
    interval_o = ServerInterval(pentest, mongoInstance.findInDb(pentest, "intervals", {"_id": ObjectId(interval_iid)}, False))
    res = mongoInstance.deleteFromDb(pentest, "intervals", {"_id": ObjectId(interval_iid)}, False)
    parent_wave = mongoInstance.findInDb(pentest, "waves", {"wave": interval_o.wave}, False)
    if parent_wave is not None:
        mongoInstance.send_notify(pentest,
                                "waves", parent_wave["_id"], "update", "")
        other_intervals = mongoInstance.findInDb(pentest, "waves", {"wave": interval_o.wave})
        no_interval_in_time = True
        for other_interval in other_intervals:
            other_interval = ServerInterval(pentest, other_interval)
            if fitNowTime(other_interval.dated, other_interval.datef):
                no_interval_in_time = False
                break
        if no_interval_in_time:
            tools = mongoInstance.findInDb(pentest, "tools", {"wave": interval_o.wave})
            for tool in tools:
                tool = ServerTool(pentest, tool)
                tool.setOutOfTime(pentest)
    if res is None:
        return 0
    else:
        return res.deleted_count
@permission("pentester")
def insert(pentest, body):
    mongoInstance = MongoCalendar.getInstance()
    if "_id" in body:
        del body["_id"]
    interval_o = ServerInterval(pentest, body)
    parent = interval_o.getParentId()
    ins_result = mongoInstance.insertInDb(pentest, "intervals", body, parent)
    interval_o.setToolsInTime()
    iid = ins_result.inserted_id
    return {"res":True, "iid":iid}

@permission("pentester")
def update(pentest, interval_iid, body):
    mongoInstance = MongoCalendar.getInstance()
    interval_o = ServerInterval(pentest, mongoInstance.findInDb(pentest, "intervals", {"_id": ObjectId(interval_iid)}, False))
    interval_o.setToolsInTime()
    mongoInstance.updateInDb(pentest, "intervals", {"_id":ObjectId(interval_iid)}, {"$set":body}, False, True)
    return True