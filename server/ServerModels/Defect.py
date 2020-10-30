from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Components.Utils import JSONEncoder
from core.Models.Defect import Defect
import json

mongoInstance = MongoCalendar.getInstance()

class ServerDefect(Defect):
    def __init__(self, pentest, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pentest = pentest

    def addInDb(self):
        insert(self.pentest, ToolController(self).getData())

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
        return obj["_id"]

def delete(pentest, defect_iid):
    mongoInstance.connectToDb(pentest)
    defect = ServerDefect(pentest, mongoInstance.find("defects", {"_id": ObjectId(defect_iid)}, False))
    if defect is None:
        return 0
    rmProofs(defect)
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
    data["parent"] = parent
    ins_result = mongoInstance.insert("defects", data, '')
    iid = ins_result.inserted_id
    defect_o._id = iid
    if defect_o.isAssigned():
        # Edit to global defect and insert it
        defect_o.ip = ""
        defect_o.port = ""
        defect_o.proto = ""
        defect_o.parent = ""
        defect_o.notes = ""
        defect_o.addInDb()
    return {"res":True, "iid":iid}

def update(pentest, defect_iid, data):
    mongoInstance.connectToDb(pentest)
    return mongoInstance.update("defects", {"_id":ObjectId(defect_iid)}, {"$set":data}, False, True)

def rmProofs(defect):
    """Removes all the proof file in this defect
    """
    proofs = defect.proofs
    fs = FileStorage()
    fs.open()
    remote_dirpath = defect.calcDirPath()
    fs.rmProofs(remote_dirpath)
    fs.close()
    del proofs
    defect.proofs = []
    defect.update()