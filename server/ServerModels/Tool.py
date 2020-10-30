from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Models.Tool import Tool
from core.Controllers.ToolController import ToolController

from core.Components.Utils import JSONEncoder
import json

mongoInstance = MongoCalendar.getInstance()

class ServerTool(Tool):

    def __init__(self, pentest, *args, **kwargs):
        self.pentest = pentest
        super().__init__(*args, **kwargs)

    def setOutOfTime(self, pentest):
        """Set this tool as out of time (not matching any interval in wave)
        Add "OOT" in status
        """
        if "OOT" not in self.status:
            self.status.append("OOT")
            update(pentest, self._id, {"status": self.status})

    def setOutOfScope(self, pentest):
        """Set this tool as in scope (is matching at least one scope in wave)
        Remove "OOS" from status
        """
        if not "OOS" in self.status:
            self.status.append("OOS")
            update(pentest, self._id, {"status": self.status})
    
    def addInDb(self):
        insert(self.pentest, ToolController(self).getData())

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        mongoInstance.connectToDb(pentest)
        results = mongoInstance.find("tools", pipeline)
        for result in results:
            yield(ServerTool(pentest, result))

    def setInScope(self):
        """Set this tool as out of scope (not matching any scope in wave)
        Add "OOS" in status
        """
        if "OOS" in self.status:
            self.status.remove("OOS")
            update(pentest, self._id, ToolController(self).getData())

    def setInTime(self):
        """Set this tool as in time (matching any interval in wave)
        Remove "OOT" from status
        """
        if "OOT" in self.status:
            self.status.remove("OOT")
            update(pentest, self._id, ToolController(self).getData())

    def delete(self):
        """
        Delete the tool represented by this model in database.
        """
        delete(self.pentest, self._id)

    def getParentId(self):
        mongoInstance.connectToDb(self.pentest)
        try:
            if self.lvl == "wave":
                wave = mongoInstance.find("waves", {"wave": self.wave}, False)
                return wave["_id"]
            elif self.lvl == "network" or self.lvl == "domain":
                return mongoInstance.find("scopes", {"wave": self.wave, "scope": self.scope}, False)["_id"]
            elif self.lvl == "ip":
                return mongoInstance.find("ips", {"ip": self.ip}, False)["_id"]
            else:
                return mongoInstance.find("ports", {"ip": self.ip, "port": self.port, "proto": self.proto}, False)["_id"]
        except TypeError:
            # None type returned:
            return None


def delete(pentest, tool_iid):
    mongoInstance.connectToDb(pentest)
    if not mongoInstance.isUserConnected():
        return "Not connected", 503
    res = mongoInstance.delete("tools", {"_id": ObjectId(tool_iid)}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count

def insert(pentest, data):
    mongoInstance.connectToDb(pentest)
    if not mongoInstance.isUserConnected():
        return "Not connected", 503
    tool_o = ServerTool(pentest, data)
    # Checking unicity
    base = tool_o.getDbKey()
    existing = mongoInstance.find("tools", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    # Inserting scope
    parent = tool_o.getParentId()
    res_insert = mongoInstance.insert("tools", base, parent)
    ret = res_insert.inserted_id
    tool_o._id = ret
    # adding the appropriate tools for this scope.
    return {"res":True, "iid":ret}


def update(pentest, tool_iid, data):
    mongoInstance.connectToDb(pentest)
    if not mongoInstance.isUserConnected():
        return "Not connected", 503
    return mongoInstance.update("tools", {"_id":ObjectId(tool_iid)}, {"$set":data}, False, True)

