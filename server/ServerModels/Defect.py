from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Components.Utils import JSONEncoder
from core.Models.Defect import Defect
from core.Controllers.DefectController import DefectController
from server.FileManager import getProofPath
from server.ServerModels.Element import ServerElement
import json
import os

mongoInstance = MongoCalendar.getInstance()

class ServerDefect(Defect, ServerElement):
    def __init__(self, pentest="", *args, **kwargs):
        super().__init__(*args, **kwargs)
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        mongoInstance.connectToDb(self.pentest)


    def addInDb(self):
        return insert(self.pentest, DefectController(self).getData())

    def update(self):
        return update("defects", {"_id":ObjectId(self._id)}, {"$set":DefectController(self).getData()}, False, True)

    def getParentId(self):
        try:
            port = self.port
        except AttributeError:
            port = None
        if port is None:
            port = ""
        mongoInstance.connectToDb(self.pentest)
        if port == "":
            obj = mongoInstance.find("ips", {"ip": self.ip}, False)
        else:
            obj = mongoInstance.find(
                "ports", {"ip": self.ip, "port": self.port, "proto": self.proto}, False)
        if obj is None:
            return ""
        return obj.get("_id", None)

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        mongoInstance.connectToDb(pentest)
        ds = mongoInstance.find(cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            # disabling this error as it is an abstract function
            yield cls(pentest, d)  #  pylint: disable=no-value-for-parameter
    
    @classmethod
    def fetchObject(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        mongoInstance.connectToDb(pentest)
        ds = mongoInstance.find(cls.coll_name, pipeline, False)
        if ds is None:
            return None
        return cls(pentest, d) 

def delete(pentest, defect_iid):
    mongoInstance.connectToDb(pentest)
    defect = ServerDefect(pentest, mongoInstance.find("defects", {"_id": ObjectId(defect_iid)}, False))
    if defect is None:
        return 0
    proofs_path = getProofPath(pentest, defect_iid)
    if os.path.isdir(proofs_path):
        files = os.listdir(proofs_path)
        for filetodelete in files:
            os.remove(os.path.join(proofs_path, filetodelete))
        os.rmdir(proofs_path)
    res = mongoInstance.delete("defects", {"_id": ObjectId(defect_iid)}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count

def insert(pentest, data):
    mongoInstance.connectToDb(pentest)
    defect_o = ServerDefect(pentest, data)
    base = defect_o.getDbKey()
    existing = mongoInstance.find("defects", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    parent = defect_o.getParentId()
    if "_id" in data:
        del data["_id"]
    ins_result = mongoInstance.insert("defects", data, parent)
    iid = ins_result.inserted_id
    defect_o._id = iid
    if defect_o.isAssigned():
        # Edit to global defect and insert it
        defect_o.ip = ""
        defect_o.port = ""
        defect_o.proto = ""
        defect_o.parent = ""
        defect_o.notes = ""
        insert(pentest, DefectController(defect_o).getData())
    return {"res":True, "iid":iid}

def update(pentest, defect_iid, data):
    mongoInstance.connectToDb(pentest)
    return mongoInstance.update("defects", {"_id":ObjectId(defect_iid)}, {"$set":data}, False, True)

