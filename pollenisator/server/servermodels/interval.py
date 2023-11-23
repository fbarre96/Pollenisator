from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.interval import Interval
from pollenisator.server.servermodels.tool import ServerTool
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.core.components.utils import JSONEncoder, fitNowTime, stringToDate
import json
from pollenisator.server.permission import permission

class ServerInterval(Interval, ServerElement):

    def __init__(self, pentest="", *args, **kwargs):
        super().__init__(*args, **kwargs)
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
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
        dbclient = DBClient.getInstance()
        res = dbclient.findInDb(self.pentest, "waves", {"wave": self.wave}, False)
        if res:
            return res.get("_id", None)
        return None

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        dbclient = DBClient.getInstance()

        ds = dbclient.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            # disabling this error as it is an abstract function
            yield cls(pentest, d)  #  pylint: disable=no-value-for-parameter

@permission("pentester")
def delete(pentest, interval_iid):
    dbclient = DBClient.getInstance()
    interval_o = ServerInterval(pentest, dbclient.findInDb(pentest, "intervals", {"_id": ObjectId(interval_iid)}, False))
    res = dbclient.deleteFromDb(pentest, "intervals", {"_id": ObjectId(interval_iid)}, False)
    parent_wave = dbclient.findInDb(pentest, "waves", {"wave": interval_o.wave}, False)
    if parent_wave is not None:
        dbclient.send_notify(pentest,
                                "waves", parent_wave["_id"], "update", "")
        other_intervals = dbclient.findInDb(pentest, "waves", {"wave": interval_o.wave})
        no_interval_in_time = True
        for other_interval in other_intervals:
            other_interval = ServerInterval(pentest, other_interval)
            if fitNowTime(other_interval.dated, other_interval.datef):
                no_interval_in_time = False
                break
        if no_interval_in_time:
            tools = dbclient.findInDb(pentest, "tools", {"wave": interval_o.wave})
            for tool in tools:
                tool = ServerTool(pentest, tool)
                tool.setOutOfTime(pentest)
    if res is None:
        return 0
    else:
        return res
@permission("pentester")
def insert(pentest, body):
    dbclient = DBClient.getInstance()
    if "_id" in body:
        del body["_id"]
    interval_o = ServerInterval(pentest, body)
    parent = interval_o.getParentId()
    try:
        stringToDate(body.get("dated"))
        stringToDate(body.get("datef"))
    except ValueError as e:
        return "Invalid date format, expected '%d/%m/%Y %H:%M:%S'", 400
    ins_result = dbclient.insertInDb(pentest, "intervals", body, parent)
    interval_o.setToolsInTime()
    iid = ins_result.inserted_id
    return {"res":True, "iid":iid}, 200

@permission("pentester")
def update(pentest, interval_iid, body):
    dbclient = DBClient.getInstance()
    interval_o = ServerInterval(pentest, dbclient.findInDb(pentest, "intervals", {"_id": ObjectId(interval_iid)}, False))
    interval_o.setToolsInTime()
    dbclient.updateInDb(pentest, "intervals", {"_id":ObjectId(interval_iid)}, {"$set":body}, False, True)
    return True