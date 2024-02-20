"""
handle the defect related API calls
"""
from datetime import datetime
from typing import Any, Dict, Iterator, List, Tuple, Union, cast
from typing_extensions import TypedDict
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.defect import Defect
from pollenisator.core.models.element import Element
from pollenisator.server.permission import permission
from pollenisator.core.components.utils import getMainDir, JSONDecoder
from pollenisator.server.modules.filemanager.filemanager import listFiles, rmProof
import threading
import os
import re
import json
sem = threading.Semaphore() 
DefectInsertResult = TypedDict('DefectInsertResult', {'res': bool, 'iid': ObjectId})
RemarkInsertResult = TypedDict('RemarkInsertResult', {'res': bool, 'iid': ObjectId})
ExportDefectTemplates = TypedDict('ExportDefectTemplates', {'defects': List[Dict[str, Any]], 'remarks': List[Dict[str, Any]]})

def getProofPath(pentest: str, defect_iid: str) -> str:
    """
    Get the local path for the proof of a defect.

    Args:
        pentest (str): The name of the pentest.
        defect_iid (str): The id of the defect.

    Returns:
        str: The local path for the proof of the defect.
    """
    local_path = os.path.join(getMainDir(), "files")
    return os.path.join(local_path, pentest, "proof", str(defect_iid))

@permission("pentester")
def delete(pentest: str, defect_iid: str) -> int:
    """
    Delete a defect from the database using its id. If the defect is not assigned to a pentest object, 
    it's considered a report defect and all defects with a higher index are updated. 
    If the pentest is not "pollenisator", the proof files for the defect are also deleted.
    
    Args:
        pentest (str): the pentest uuid or "pollenisator"
        defect_iid (str): the defect id to delete from the database
    
    Returns:
        int: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
    """
    dbclient = DBClient.getInstance()
    defect = Defect(pentest, dbclient.findInDb(pentest, "defects", {"_id": ObjectId(defect_iid)}, False))
    if defect is None:
        return 0
    if not defect.isAssigned() and pentest != "pollenisator":
        # if not assigned to a pentest object it's a report defect (except in pollenisator db where it's a defect template)
        globalDefects_iterator = Defect.fetchObjects(pentest, {"target_id":""})
        if globalDefects_iterator is None:
            globalDefects: List[Defect] = []
        else:
            globalDefects = cast(List[Defect], globalDefects_iterator)
        for globalDefect in globalDefects:
            if int(globalDefect.index) > int(defect.index):
                update(pentest, globalDefect.getId(), {"index":str(int(globalDefect.index) - 1)})
        thisAssignedDefects = Defect.fetchObjects(pentest, {"global_defect": ObjectId(defect_iid)})
        if thisAssignedDefects is not None:
            for thisAssignedDefect in thisAssignedDefects:
                delete(pentest, thisAssignedDefect.getId())
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
        return res

@permission("pentester")
def insert(pentest: str, body: Dict[str, Any]) -> Union[DefectInsertResult, Tuple[str, int]]:
    """
    Insert a new defect into the database.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the details of the defect to be inserted.

    Returns:
        Union[Dict[str, Union[bool, Any]], str]: A dictionary with keys "res" and "iid" if the operation was successful, 
        or a string error message otherwise.
    """
    try:
        dbclient = DBClient.getInstance()
        if "creation_time" in body:
            del body["creation_time"]
        defect_o = Defect(pentest, body)
        if not defect_o.isAssigned():
            sem.acquire()
        base = defect_o.getDbKey()

        existing = dbclient.findInDb(pentest, "defects", base, False)
        if existing is not None:
            sem.release()
            return {"res":False, "iid":existing["_id"]}
        if defect_o.target_id != "" and defect_o.target_type == "":
            sem.release()
            return "If a target_id is specified, a target_type should be specified to", 400
        parent = defect_o.getParentId()
        if "_id" in body:
            del body["_id"]
        if pentest != "pollenisator" and not defect_o.isAssigned():
            insert_pos = findInsertPosition(pentest, body["risk"])
            save_insert_pos = insert_pos
            defects_to_edit = []

            defect_to_edit_o = Defect.fetchObject(pentest, {"target_id":"", "index":str(insert_pos)})
            if defect_to_edit_o is not None:
                defects_to_edit.append(defect_to_edit_o)
            while defect_to_edit_o is not None:
                insert_pos+=1
                defect_to_edit_o = Defect.fetchObject(pentest, {"target_id":"",  "index":str(insert_pos)})
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
        if isinstance(body.get("type", []), str):
            body["type"] = body.get("type", "").split(",")
        ins_result = dbclient.insertInDb(pentest, "defects", body, parent)
        iid = ins_result.inserted_id
        defect_o._id = iid

        if defect_o.isAssigned():
            # Edit to global defect and insert it
            defect_o.target_id = ""
            defect_o.target_type = ""
            defect_o.parent = ""
            defect_o.notes = ""
            insert_res = insert(pentest, defect_o.getData())
            dbclient.updateInDb(pentest, "defects", {"_id":ObjectId(iid)}, {"$set":{"global_defect": insert_res["iid"]}})
    except Exception as e:
        sem.release()
        raise(e)
    sem.release()
    return {"res":True, "iid":iid}

def insert_remark(pentest: str, body: Dict[str, Any]) -> RemarkInsertResult:
    """
    Insert a new remark into the database. If a remark with the same id or title already exists, 
    the function will return the id of the existing remark.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the remark details.

    Returns:
        RemarkInsertResult: A dictionary containing the result of the operation and the id of the inserted remark.
    """
    dbclient = DBClient.getInstance()
    base = {"id":body.get("id", body.get("title", ""))}
    existing = dbclient.findInDb(pentest, "remarks", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    body["id"] = body.get("id", body.get("title", ""))
    ins_result = dbclient.insertInDb(pentest, "remarks", body)
    iid = ins_result.inserted_id
    return {"res":True, "iid":iid}

def update_remark(pentest: str, remark_iid: ObjectId, body: Dict[str, Any]) -> None:
    """
    Update a remark in the database using its id. The "_id" field in the body is ignored.

    Args:
        pentest (str): The name of the pentest.
        remark_iid (ObjectId): The id of the remark to be updated.
        body (Dict[str, Any]): A dictionary containing the new remark details.
    """
    dbclient = DBClient.getInstance()
    dbclient.updateInDb(pentest, "remarks", {"_id":ObjectId(remark_iid)}, {"$set":body}, False, True)

@permission("pentester")
def findInsertPosition(pentest: str, risk: str) -> int:
    """
    Find the position to insert a new defect based on its risk level. The position is determined by the highest index of 
    defects with the same or higher risk level.

    Args:
        pentest (str): The name of the pentest.
        risk (str): The risk level of the defect.

    Returns:
        int: The position to insert the new defect.
    """
    riskLevels = ["Critical", "Major",  "Important", "Minor"] # TODO do not hardcode those things
    riskLevelPos = riskLevels.index(risk)
    highestInd = 0
    for risklevel_i, riskLevel in enumerate(riskLevels):
        if risklevel_i > riskLevelPos:
            break
        globalDefects = Defect.fetchObjects(pentest, {"target_id":"", "risk":riskLevel})
        globalDefects = cast(Iterator[Defect], globalDefects)
        for globalDefect in globalDefects:
            highestInd = max(int(globalDefect.index)+1, highestInd)
    return highestInd

def _findProofsInDescription(description: str) -> Iterator[re.Match[str]]:
    """
    Find all image references in a description. The function looks for markdown image syntax (![alt text](url)) 
    where the url does not start with "http".

    Args:
        description (str): The description to search for image references.

    Returns:
        Iterator[re.Match[str]]:: An iterator yielding match objects for each image reference found.
    """
    regex_images = r"!\[.*\]\(((?!http).*)\)" # regex to find images in markdown
    return re.finditer(regex_images, description)

@permission("pentester")
def update(pentest: str, defect_iid: ObjectId, body: Dict[str, Any]) -> Union[bool, Tuple[str, int]]:
    """
    Update a defect in the database.

    Args:
        pentest (str): The name of the pentest.
        defect_iid (ObjectId): The id of the defect to be updated.
        body (Dict[str, Any]): A dictionary containing the details of the defect to be updated.

    Returns:
        Union[bool, Tuple[str, int]]: True if the operation was successful, or a tuple containing an error message and 
        an error code otherwise.
    """
    dbclient = DBClient.getInstance()
    defect_o = Defect.fetchObject(pentest, {"_id":ObjectId(defect_iid)})
    defect_o = cast(Defect, defect_o)
    if defect_o is None:
        return "This defect does not exist", 404

    oldRisk = defect_o.risk
    if not defect_o.isAssigned() and pentest != "pollenisator":
        if body.get("risk", None) is not None and pentest != "pollenisator":
            if body["risk"] != oldRisk:
                insert_pos = str(findInsertPosition(pentest, body["risk"]))
                if int(insert_pos) > int(defect_o.index):
                    insert_pos = str(int(insert_pos)-1)
                defectTarget = Defect.fetchObject(pentest, {"target_id":"", "index":insert_pos})
                if defectTarget is not None:
                    moveDefect(pentest, defect_iid, defectTarget.getId())
            if "index" in body:
                del body["index"]
    if pentest != "pollenisator":
        body["proofs"] = set()
        proof_groups = _findProofsInDescription(body.get("description", ""))
        existing_proofs_to_remove = listFiles(pentest, defect_iid, "proof")
        for proof_group in proof_groups:
            if proof_group.group(1) in existing_proofs_to_remove:
                existing_proofs_to_remove.remove(proof_group.group(1))
            body["proofs"].add(proof_group.group(1))
        for proof_to_remove in existing_proofs_to_remove:
            rmProof(pentest, defect_iid, proof_to_remove)
        body["proofs"] = list(body["proofs"])
    dbclient.updateInDb(pentest, "defects", {"_id":ObjectId(defect_iid)}, {"$set":body}, False, True)
    return True

@permission("pentester")
def getGlobalDefects(pentest: str) -> List[Dict[str, Any]]:
    """
    Get all global defects for a pentest. Global defects are defects that are not assigned to a specific target.

    Args:
        pentest (str): The name of the pentest.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, each representing a global defect. The defects are ordered by their index.
    """
    defects = Defect.fetchObjects(pentest, {"target_id": ""})
    if defects is None:
        return []
    defects_ordered = []
    for defect in defects:
        defects_ordered.append(defect.getData())
    return sorted(defects_ordered, key=lambda defect: int(defect["index"]))

@permission("pentester")
def moveDefect(pentest: str, defect_id_to_move: str, target_id: str) -> Union[Tuple[str, int], int]:
    """
    Move a global defect to a new position. The position is determined by the index of another global defect.

    Args:
        pentest (str): The name of the pentest.
        defect_id_to_move (str): The id of the defect to be moved.
        target_id (str): The id of the defect that determines the new position.

    Returns:
        Union[Tuple[str, int], int]: A tuple containing an error message and status code if the defect to be moved or the 
        target defect does not exist, otherwise the new index of the moved defect.
    """
    defect_to_move = Defect.fetchObject(pentest, {"_id":ObjectId(defect_id_to_move), "target_id":""})
    if defect_to_move is None:
        return "This global defect does not exist", 404
    defect_to_move = cast(Defect, defect_to_move)
    defects_ordered = getGlobalDefects(pentest)
    defect_target = Defect.fetchObject(pentest, {"_id":ObjectId(target_id), "target_id":""})
    if defect_target is None:
        return "the target global defect does not exist", 404
    defect_target = cast(Defect, defect_target)
    target_ind = int(defect_target.index)
    defect_to_move_ind = int(defect_to_move.index)
    del defects_ordered[defect_to_move_ind]
    defects_ordered.insert(target_ind, defect_to_move.getData())
    for defect_i in range(min(defect_to_move_ind, target_ind), len(defects_ordered)):
        defect_o = Defect(pentest, defects_ordered[defect_i])
        update(pentest, defect_o.getId(), {"index":str(defect_i)})
    update(pentest, defect_to_move.getId(), {"index":str(target_ind)})
    return target_ind

@permission("user")
def importDefectTemplates(upfile: Any) -> Union[Tuple[str, int], bool]:
    """
    Import defect templates from a JSON file. The file should contain a list of defects and a list of remarks. 
    Each defect and remark is inserted into the "pollenisator" database. If a defect or remark with the same id already exists, 
    it is updated with the new details.

    Args:
        upfile (Any): The uploaded file containing the defect templates.

    Returns:
        Union[Tuple[str, int], bool]: A tuple containing an error message and status code if the file is not valid JSON, 
        otherwise True indicating the operation was successful.
    """
    try:
        file_content = json.loads(upfile.stream.read())
        defects = file_content.get("defects", [])
        for defect in defects:
            invalids = ["target_id", "target_type",  "scope"]
            for invalid in invalids:
                if invalid in defect:
                    del defect[invalid]
            res = insert("pollenisator", defect)
            if not res["res"]:
                update("pollenisator", res["iid"], defect)
        remarks = file_content.get("remarks", [])
        for remark in remarks:
            res = insert_remark("pollenisator", remark)
            if not res["res"]:
                update_remark("pollenisator", res["iid"], remark)
    except Exception as e:
        return "Invalid json sent : "+str(e), 400
    return True

@permission("user")
def exportDefectTemplates(**_kwargs: Any) -> ExportDefectTemplates:
    """
    Export all defect and remark templates. The templates are extracted from the "pollenisator" database.

    Args:
        **kwargs (Any): Additional keyword arguments.

    Returns:
        Dict[str, List[Dict[str, Any]]]: A dictionary containing two lists: one for defect templates and one for remark templates.
    """
    dbclient = DBClient.getInstance()
    templates_defects = dbclient.findInDb("pollenisator", "defects", {}, True)
    templates_remarks = dbclient.findInDb("pollenisator", "remarks", {}, True)
    res: ExportDefectTemplates = {"defects": [], "remarks": []}
    for template in templates_defects:
        t = template
        del t['_id']
        res["defects"].append(t)
    for template in templates_remarks:
        t = template
        del t['_id']
        res["remarks"].append(t)
    return res

@permission("user")
def findDefectTemplate(body: Dict[str, Any]) -> Union[Dict[str, Any], Tuple[str, int]]:
    """
    Find a defect template in the "pollenisator" database using a set of criteria. If the "_id" field is present in the 
    criteria, it is converted to an ObjectId.

    Args:
        body (Dict[str, Any]): A dictionary containing the search criteria.

    Returns:
        Union[Dict[str, Any], Tuple[str, int]]: The found defect template as a dictionary, or a tuple containing an error 
        message and status code if no template was found.
    """
    dbclient = DBClient.getInstance()
    if "_id" in body:
        if str(body["_id"]).startswith("ObjectId|"):
            body["_id"] = ObjectId(body["_id"].split("|")[1])
        else:
            body["_id"] = ObjectId(body["_id"])
    res = dbclient.findInDb("pollenisator", "defects", body, False)
    if res is not None:
        return res
    return  "No defect template found with this criteria", 404

@permission("user")
def insertDefectTemplate(body: Dict[str, Any]) -> Union[DefectInsertResult, Tuple[str, int]]:
    """
    Insert a new defect template into the "pollenisator" database. If a template with the same id or title already exists, 
    the function will return the id of the existing template.

    Args:
        body (Dict[str, Any]): A dictionary containing the defect template details.

    Returns:
        Union[DefectInsertResult, Tuple[str, int]]: The id of the inserted template, or a tuple containing an error message and status 
        code if the insertion was unsuccessful.
    """
    res: Union[DefectInsertResult, Tuple[str, int]] = insert("pollenisator", body)
    return res

@permission("user")
def updateDefectTemplate(iid: str, body: Dict[str, Any]) -> Union[bool, Tuple[str, int]]:
    """
    Update a defect template in the "pollenisator" database using its id. The "_id" field in the body is ignored.

    Args:
        iid (str): The id of the defect template to be updated.
        body (Dict[str, Any]): A dictionary containing the new defect template details.

    Returns:
        Union[bool, Tuple[str, int]]: True if the operation was successful, otherwise a tuple containing an error message 
        and status code.
    """
    res: Union[bool, Tuple[str, int]] = update("pollenisator", iid, body)
    return res

@permission("user")
def deleteDefectTemplate(iid: str) -> Union[int, Any]:
    """
    Delete a defect template from the "pollenisator" database using its id.

    Args:
        iid (str): The id of the defect template to be deleted.

    Returns:
        Union[int, Any]: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
    """
    return delete("pollenisator", iid)

@permission("pentester")
def getTargetRepr(pentest: str, body: Union[str, List[str]]) -> Union[Tuple[str, int], Dict[str, str]]:
    """
    Get a string representation of the target of each defect in the provided list.

    Args:
        pentest (str): The name of the pentest.
        body (Union[str, List[str]]): A list of defect ids or a string representation of such a list.

    Returns:
        Dict[str, str]: A dictionary mapping each defect id to a string representation of its target.
    """
    dbclient = DBClient.getInstance()
    if isinstance(body, str):
        body = json.loads(body, cls=JSONDecoder)
    if not isinstance(body, list):
        return "Invalid input", 400
    iids_list = []
    for str_iid in body:
        if "ObjectId|" in str_iid:
            iid = ObjectId(str_iid.split("ObjectId|")[1])
        else:
            iid = ObjectId(str_iid)
        iids_list.append(iid)
    defects = dbclient.findInDb(pentest, "defects", {"_id": {"$in": iids_list}}, True)
    ret = {}
    for data in defects:
        class_element = Element.classFactory(data["target_type"])
        if class_element is not None:
            elem = class_element.fetchObject(pentest, {"_id": ObjectId(data["target_id"])})
            if elem is None:
                ret_str = "Target not found"
            else:
                ret_str = elem.getDetailedString()
            ret[str(data["_id"])] = ret_str
        else:
            ret[str(data["_id"])] = "Target not found"
    return ret
