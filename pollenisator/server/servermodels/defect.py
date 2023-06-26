from datetime import datetime
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.defect import Defect
from pollenisator.core.controllers.defectcontroller import DefectController
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.server.permission import permission
from pollenisator.core.components.utils import getMainDir
import threading
import os
import json
sem = threading.Semaphore() 

class ServerDefect(Defect, ServerElement):
    def __init__(self, pentest="", *args, **kwargs):
        dbclient = DBClient.getInstance()
        super().__init__(*args, **kwargs)
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")


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
        dbclient = DBClient.getInstance()
        if port == "":
            obj = dbclient.findInDb(self.pentest, "ips", {"ip": self.ip}, False)
        else:
            obj = dbclient.findInDb(self.pentest,
                "ports", {"ip": self.ip, "port": self.port, "proto": self.proto}, False)
        if obj is None:
            return ""
        return obj.get("_id", None)




def getProofPath(pentest, defect_iid):
    local_path = os.path.join(getMainDir(), "files")

    return os.path.join(local_path, pentest, "proof", str(defect_iid))

@permission("pentester")
def delete(pentest, defect_iid):
    dbclient = DBClient.getInstance()
    defect = ServerDefect(pentest, dbclient.findInDb(pentest, "defects", {"_id": ObjectId(defect_iid)}, False))
    if defect is None:
        return 0
    if not defect.isAssigned() and pentest != "pollenisator":
        # if not assigned to a pentest object it's a report defect (except in pollenisator db where it's a defect template)
        globalDefects = ServerDefect.fetchObjects(pentest, {"ip":""})
        for globalDefect in globalDefects:
            if int(globalDefect.index) > int(defect.index):
                update(pentest, globalDefect.getId(), {"index":str(int(globalDefect.index) - 1)})
        thisAssignedDefects = ServerDefect.fetchObjects(pentest, {"global_defect": ObjectId(defect_iid)})
        for thisAssignedDefects in thisAssignedDefects:
            delete(pentest, thisAssignedDefects.getId())
    if pentest != "pollenisator":
        proofs_path = getProofPath(pentest, defect_iid)
        if os.path.isdir(proofs_path):
            files = os.listdir(proofs_path)
            for filetodelete in files:
                os.remove(os.path.join(proofs_path, filetodelete))
            os.rmdir(proofs_path)
    
    res = dbclient.deleteFromDb(pentest, "defects", {"_id": ObjectId(defect_iid)}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count

@permission("pentester")
def insert(pentest, body):
    
    try:
        dbclient = DBClient.getInstance()
        if "creation_time" in body:
            del body["creation_time"]
        defect_o = ServerDefect(pentest, body)
        if not defect_o.isAssigned():
            sem.acquire()
        base = defect_o.getDbKey()

        existing = dbclient.findInDb(pentest, "defects", base, False)
        if existing is not None:
            sem.release()
            return {"res":False, "iid":existing["_id"]}
        if defect_o.ip.strip() == "" and defect_o.port.strip() != "":
            sem.release()
            return "If a port is specified, an ip should be specified to", 400
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
                defect_to_edit_o = ServerDefect.fetchObject(pentest, {"ip":"",  "index":str(insert_pos)})
                if defect_to_edit_o is not None:
                    defects_to_edit.append(defect_to_edit_o)
                
            for defect_to_edit in defects_to_edit:
                update(pentest, defect_to_edit.getId(), {"index":str(int(defect_to_edit.index)+1)})
            body["index"] = str(save_insert_pos)
        else:
            if "description" in body:
                del body["description"]
            if "synthesis" in body:
                del body["synthesis"]
            if "fixes" in body:
                del body["fixes"]
        body["creation_time"] = datetime.now()
        ins_result = dbclient.insertInDb(pentest, "defects", body, parent)
        iid = ins_result.inserted_id
        defect_o._id = iid

        if defect_o.isAssigned():
            # Edit to global defect and insert it
            defect_o.ip = ""
            defect_o.port = ""
            defect_o.proto = ""
            defect_o.parent = ""
            defect_o.notes = ""
            insert_res = insert(pentest, DefectController(defect_o).getData())
            dbclient.updateInDb(pentest, "defects", {"_id":ObjectId(iid)}, {"$set":{"global_defect": insert_res["iid"]}})
    except Exception as e:
        sem.release()
        raise(e)
    sem.release()
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
    dbclient = DBClient.getInstance()
    defect_o = ServerDefect.fetchObject(pentest, {"_id":ObjectId(defect_iid)})
    if defect_o is None:
        return "This defect does not exist", 404

    oldRisk = defect_o.risk
    if not defect_o.isAssigned():
        if body.get("risk", None) is not None and pentest != "pollenisator":
            if body["risk"] != oldRisk:
                insert_pos = str(findInsertPosition(pentest, body["risk"]))
                if int(insert_pos) > int(defect_o.index):
                    insert_pos = str(int(insert_pos)-1)
                defectTarget = ServerDefect.fetchObject(pentest, {"ip":"", "index":insert_pos})
                moveDefect(pentest, defect_iid, defectTarget.getId())
            if "index" in body:
                del body["index"]
    res = dbclient.updateInDb(pentest, "defects", {"_id":ObjectId(defect_iid)}, {"$set":body}, False, True)
    return True
    
@permission("pentester")
def getGlobalDefects(pentest):
    defects = ServerDefect.fetchObjects(pentest, {"ip": ""})
    if defects is None:
        return []
    defects_ordered = []
    for defect in defects:
        defects_ordered.append(DefectController(defect).getData())
    return sorted(defects_ordered, key=lambda defect: int(defect["index"]))
    
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

@permission("user")
def importDefectTemplates(upfile):
    try:
        defects = json.loads(upfile.stream.read())
        for defect in defects:
            invalids = ["ip", "port", "proto", "scope"]
            for invalid in invalids:
                if invalid in defect:
                    del defect[invalid]
            insert("pollenisator", defect)
    except Exception as e:
        return "Invalid json sent", 400
    return True

@permission("user")
def exportDefectTemplates(**kwargs):
    dbclient = DBClient.getInstance()
    templates = dbclient.findInDb("pollenisator", "defects", {}, True)
    res = []
    for template in templates:
        t = template
        del t['_id']
        res.append(t)
    return res

@permission("user")
def insertDefectTemplate(body):
    return insert("pollenisator", body)

@permission("user")
def updateDefectTemplate(iid, body):
    return update("pollenisator", iid, body)

@permission("user")
def deleteDefectTemplate(iid):
    return delete("pollenisator", iid)
