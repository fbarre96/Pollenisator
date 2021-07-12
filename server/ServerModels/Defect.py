from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Components.Utils import JSONEncoder
from core.Models.Defect import Defect
from core.Controllers.DefectController import DefectController
from server.FileManager import getProofPath
from server.ServerModels.Element import ServerElement
from server.permission import permission
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
        return update("defects", ObjectId(self._id), DefectController(self).getData())

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
        d = mongoInstance.find(cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls(pentest, d) 

@permission("pentester")
def delete(pentest, defect_iid):
    mongoInstance.connectToDb(pentest)
    defect = ServerDefect(pentest, mongoInstance.find("defects", {"_id": ObjectId(defect_iid)}, False))
    if defect is None:
        return 0
    if not defect.isAssigned():
        globalDefects = ServerDefect.fetchObjects(pentest, {"ip":""})
        for globalDefect in globalDefects:
            if int(globalDefect.index) > int(defect.index):
                update(pentest, globalDefect.getId(), {"index":str(int(globalDefect.index) - 1)})

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
@permission("pentester")
def insert(pentest, body):
    mongoInstance.connectToDb(pentest)
    defect_o = ServerDefect(pentest, body)
    base = defect_o.getDbKey()
    existing = mongoInstance.find("defects", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    parent = defect_o.getParentId()
    if "_id" in body:
        del body["_id"]
    if not defect_o.isAssigned():
        insert_pos = findInsertPosition(pentest, body["risk"])
        save_insert_pos = insert_pos
        defects_to_edit = []
        
        defect_to_edit_o = ServerDefect.fetchObject(pentest, {"ip":"", "index":str(insert_pos)})
        if defect_to_edit_o is not None:
            defects_to_edit.append(defect_to_edit_o)
        while defect_to_edit_o is not None:
            insert_pos+=1
            defect_to_edit_o = ServerDefect.fetchObject(pentest, {"ip":"", "index":str(insert_pos)})
            if defect_to_edit_o is not None:
                defects_to_edit.append(defect_to_edit_o)
            
        for defect_to_edit in defects_to_edit:
            print("Update defect index to "+str(int(defect_to_edit.index)+1))
            update(pentest, defect_to_edit.getId(), {"index":str(int(defect_to_edit.index)+1)})
        body["index"] = str(save_insert_pos)
    ins_result = mongoInstance.insert("defects", body, parent)
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
@permission("pentester")
def findInsertPosition(pentest, risk):
    riskLevels = ["Critical", "Major",  "Important", "Minor"] # TODO do not hardcode those things
    riskLevelPos = riskLevels.index(risk)
    highestInd = 0
    for risklevel_i, riskLevel in enumerate(riskLevels):
        if risklevel_i > riskLevelPos:
            break
        globalDefects = ServerDefect.fetchObjects(pentest, {"ip":"", "risk":riskLevel})
        for globalDefect in globalDefects:
            highestInd = max(int(globalDefect.index)+1, highestInd)
    return highestInd
@permission("pentester")
def update(pentest, defect_iid, body):
    mongoInstance.connectToDb(pentest)
    defect_o = ServerDefect.fetchObject(pentest, {"_id":ObjectId(defect_iid)})
    if defect_o is None:
        return "This defect does not exist", 404
    oldRisk = defect_o.risk
    if not defect_o.isAssigned():
        if body.get("risk", None) is not None:
            if body["risk"] != oldRisk:
                insert_pos = str(findInsertPosition(pentest, body["risk"]))
                if int(insert_pos) > int(defect_o.index):
                    insert_pos = str(int(insert_pos)-1)
                defectTarget = ServerDefect.fetchObject(pentest, {"ip":"", "index":insert_pos})
                moveDefect(pentest, defect_iid, defectTarget.getId())
            if "index" in body:
                del body["index"]
    res = mongoInstance.update("defects", {"_id":ObjectId(defect_iid)}, {"$set":body}, False, True)
    return res
@permission("pentester")
def getGlobalDefects(pentest):
    defects = ServerDefect.fetchObjects(pentest, {"ip": ""})
    d_list = {}
    if defects is None:
        return []
    for defect in defects:
        d_list[int(defect.index)] = defect
    keys_ordered = sorted(list(d_list.keys()))
    defects_ordered = []
    for i in range(len(keys_ordered)):
        defect_o = d_list[keys_ordered[i]]
        defects_ordered.append(DefectController(defect_o).getData())
    return defects_ordered
@permission("pentester")
def moveDefect(pentest, defect_id_to_move, target_id):
    defect_to_move = ServerDefect.fetchObject(pentest, {"_id":ObjectId(defect_id_to_move), "ip":""})
    if defect_to_move is None:
        return "This global defect does not exist", 404
    defects_ordered = getGlobalDefects(pentest)
    defect_target = ServerDefect.fetchObject(pentest, {"_id":ObjectId(target_id), "ip":""})
    if defect_target is None:
        return "the target global defect does not exist", 404
    target_ind = int(defect_target.index)
    defect_to_move_ind = int(defect_to_move.index)
    del defects_ordered[defect_to_move_ind]
    defects_ordered.insert(target_ind, DefectController(defect_to_move).getData())
    for defect_i in range(min(defect_to_move_ind, target_ind), len(defects_ordered)):
        defect_o = ServerDefect(pentest, defects_ordered[defect_i])
        update(pentest, defect_o.getId(), {"index":str(defect_i)})
    update(pentest, defect_to_move.getId(), {"index":str(target_ind)})
    return target_ind