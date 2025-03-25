"""
handle the defect related API calls
"""
import re
from typing import Any, Dict, List, Tuple, Union, cast
from typing_extensions import TypedDict
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.defect import Defect
from pollenisator.server.permission import permission
from pollenisator.core.components.utils import  JSONDecoder
import json
import datetime
DefectInsertResult = TypedDict('DefectInsertResult', {'res': bool, 'iid': ObjectId})
RemarkInsertResult = TypedDict('RemarkInsertResult', {'res': bool, 'iid': ObjectId})
ExportDefectTemplates = TypedDict('ExportDefectTemplates', {'defects': List[Dict[str, Any]], 'remarks': List[Dict[str, Any]]})

ErrorStatus = Tuple[str, int]

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
    defect =  Defect.fetchObject(pentest, {"_id":ObjectId(defect_iid)})
    if defect is None:
        return 0
    defect = cast(Defect, defect)
    return defect.deleteFromDb()


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
    if "_id" in body:
        del body["_id"]
    if "index" in body:
        del body["index"]
    body = json.loads(json.dumps(body), cls=JSONDecoder)
    defect = Defect(pentest, body)
    return defect.addInDb()

def insert_template_suggestion(pentest: str, body: Dict[str, Any], username: str) -> Union[DefectInsertResult, Tuple[str, int]]:
    """
    Insert a new defect template suggestion into the database.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the details of the defect template to be inserted.
        username (str): The id of the user who suggested the template.

    Returns:
        Union[Dict[str, Union[bool, Any]], str]: A dictionary with keys "res" and "iid" if the operation was successful, 
        or a string error message otherwise.
    """
    if "_id" in body:
        del body["_id"]
    if "index" in body:
        del body["index"]
    body = json.loads(json.dumps(body), cls=JSONDecoder)
    defect = Defect(pentest, body)
    dbclient = DBClient.getInstance()
    data = defect.getData()
    data["suggested_by"] = username
    data["creation_time"] = str(datetime.datetime.now())
    insert_result = dbclient.insertInDb("pollenisator", "defectssuggestions", data)
    if insert_result is None:
        return "An error occured while inserting the defect template suggestion", 500
    if insert_result.inserted_id is None:
        return "An error occured while inserting the defect template suggestion", 500
    return {"res":True, "iid":insert_result.inserted_id}


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
    return Defect.findInsertPosition(pentest, risk)


@permission("pentester")
def update(pentest: str, defect_iid: str, force: bool, body: Dict[str, Any]) -> Union[bool, Tuple[str, int]]:
    """
    Update a defect in the database.

    Args:
        pentest (str): The name of the pentest.
        defect_iid (str): The id of the defect to be updated.
        force (bool): Force the redacted state to be updated. If False, any issue will send back an error / warning as status 400.  
        body (Dict[str, Any]): A dictionary containing the details of the defect to be updated.

    Returns:
        Union[bool, Tuple[str, int]]: True if the operation was successful, or a tuple containing an error message and 
        an error code otherwise.
    """
    
    old = Defect.fetchObject(pentest, {"_id":ObjectId(defect_iid)})
    if old is None:
        return "Not found", 404
    old = cast(Defect, old)
    new_redacted_state = body.get("redacted_state")
    #STATE CHANGE
    if new_redacted_state is not None and new_redacted_state != old.redacted_state:
        #check order
        if not force:
            try:
                order = ["New", "To review", "Reviewed", "Completed"]
                if order.index(new_redacted_state) < order.index(old.redacted_state):
                    return "You are trying to rewind in the redacted state, this will delete any pending review.", 400
                if order.index(new_redacted_state) > order.index(old.redacted_state)+1:
                    return "You are trying to skip a redaction step, this could leave some review unaccepted.", 400
            except ValueError:
                return "Unknown redacted state", 400
        # Delete review if needed
        if new_redacted_state == "New" or new_redacted_state == "To review" and old.redacted_state == "Completed":
            old.delete_review()
            
        if new_redacted_state == "To review":
            old.get_review(force=True)
        old.redacted_state = new_redacted_state
        
        old.updateInDb(body)
    else:
        # Defect change
        if old.redacted_state == "To review":
            old.save_review(body)
        else:
            old.updateInDb(body)
    return True

@permission("user")
def update_template_suggestion(defect_iid: str, body: Dict[str, Any], username: str) -> Union[bool, Tuple[str, int]]:
    """
    Update a defect template suggestion in the database using its id. The "_id" field in the body is ignored.

    Args:
        defect_iid (str): The id of the defect template suggestion to be updated.
        body (Dict[str, Any]): A dictionary containing the new defect template details.
        username (str): The id of the user who suggested the template.

    Returns:
        Union[bool, Tuple[str, int]]: True if the operation was successful, or a tuple containing an error message and 
        an error code otherwise.
    """
    dbclient = DBClient.getInstance()
    
    body = json.loads(json.dumps(body), cls=JSONDecoder)
    defect = Defect("pollenisator", body)
    dbclient = DBClient.getInstance()
    new_data = defect.getData()
    if "_id" in new_data:
        del new_data["_id"]
    if "index" in new_data:
        del new_data["index"]
    old_data = dbclient.findInDb("pollenisator", "defectssuggestions", {"_id":ObjectId(defect_iid)}, False)
    if old_data is None:
        old_data = dbclient.findInDb("pollenisator", "defects", {"_id":ObjectId(defect_iid)}, False)
        if old_data is None:
            old_data = {}
    old_data |= new_data
    old_data["suggested_by"] = username
    old_data["creation_time"] = str(datetime.datetime.now())
    dbclient.updateInDb("pollenisator", "defectssuggestions", {"_id":ObjectId(defect_iid)}, {"$set":old_data}, False, True, upsert=True)
    return True

@permission("pentester")
def review(pentest: str, defect_iid: str) -> Dict[str, Any]:
    """
    Get the review of a defect. 
    Args:
        pentest (str): The name of the pentest.
        defect_iid (str): The id of the defect.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, each representing a version of the defect. The versions are ordered by their index.
    """
    defect = Defect.fetchObject(pentest, {"_id":ObjectId(defect_iid)})
    if defect is None:
        return "Not found", 404
    defect = cast(Defect, defect)
    return defect.get_review()

@permission("pentester")
def getGlobalDefects(pentest: str) -> List[Dict[str, Any]]:
    """
    Get all global defects for a pentest. Global defects are defects that are not assigned to a specific target.

    Args:
        pentest (str): The name of the pentest.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, each representing a global defect. The defects are ordered by their index.
    """
    return Defect.getGlobalDefects(pentest)

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

    return Defect.moveDefect(pentest, ObjectId(defect_id_to_move), ObjectId(target_id))

@permission("report_template_writer")
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
                update("pollenisator", res["iid"], True, defect)
        remarks = file_content.get("remarks", [])
        for remark in remarks:
            res = insert_remark("pollenisator", remark)
            if not res["res"]:
                update_remark("pollenisator", res["iid"], remark)
    except Exception as e:
        return "Invalid json sent : "+str(e), 400
    return True

@permission("user")
def exportDefectTemplates(**kwargs: Any) -> ExportDefectTemplates:
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
def getDefectSuggestion(suggestion_iid: str) -> Union[Dict[str, Any], Tuple[str, int]]:
    """
    Get a defect suggestion from the "pollenisator" database using its id.

    Args:
        suggestion_iid (str): The id of the defect suggestion.

    Returns:
        Union[Dict[str, Any], Tuple[str, int]]: A dictionary containing the defect suggestion details, or a tuple containing 
        an error message and status code if the suggestion was not found.
    """
    dbclient = DBClient.getInstance()
    suggestion = dbclient.findInDb("pollenisator", "defectssuggestions", {"_id":ObjectId(suggestion_iid)}, False)
    if suggestion is None:
        return "Not found", 404
    return suggestion

returnDefectSuggestionsType = TypedDict('returnDefectSuggestionsType', {'answers': List[Dict[str, Any]]})
@permission("user")
def findDefectSuggestions(body: Dict[str, Any]) -> Union[ErrorStatus, returnDefectSuggestionsType]:
    """
    Search for defects  or remarks suggestions in the database based on the given parameters.

    Args:
        body (Dict[str, str]): A dictionary containing the search parameters. 
            "type" (str): The type of item to search for (either "defect" or "remark").
            "terms" (str): The search terms.
            "language" (str): The language of the items to search for.
            "perimeter" (str): The perimeter of the items to search for.

    Returns:
        Union[ErrorStatus, SearchResults]: A dictionary containing any errors and the search results if successful, otherwise an error message and status code.
    """
    defect_type = body.get("type", "")
    terms = body.get("terms", "")
    lang = body.get("language", "")
    perimeter = body.get("perimeter", "")
    if defect_type == "remark":
        coll = "remarkssuggestions"
    elif defect_type == "defect":
        coll = "defectssuggestions"
    else:
        return "Invalid parameter: type must be either defect or remark.", 400
    dbclient = DBClient.getInstance()
    p = {"title":re.compile(terms, re.IGNORECASE)}
    if lang != "":
        p["language"] = re.compile(lang, re.IGNORECASE)
    if perimeter != "":
        p["perimeter"] = re.compile(perimeter, re.IGNORECASE)
    res = dbclient.findInDb("pollenisator", coll, p, True)
    if res is None:
        return {"answers":[]}
    return {"answers": [x for x in res]}

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
def insertDefectTemplate(body: Dict[str, Any], **kwargs: Dict[str, Any]) -> Union[DefectInsertResult, Tuple[str, int]]:
    """
    Insert a new defect template into the "pollenisator" database. If a template with the same id or title already exists, 
    the function will return the id of the existing template.

    Args:
        body (Dict[str, Any]): A dictionary containing the defect template details.

    Returns:
        Union[DefectInsertResult, Tuple[str, int]]: The id of the inserted template, or a tuple containing an error message and status 
        code if the insertion was unsuccessful.
    """
    is_suggestion = "admin" not in kwargs["token_info"]["scope"] and "template_writer" not in kwargs["token_info"]["scope"]
    res: Union[DefectInsertResult, Tuple[str, int]]
    if is_suggestion:
        res = insert_template_suggestion("pollenisator", body, kwargs["token_info"]["sub"])
    else:
        res = insert("pollenisator", body)
    return res

@permission("template_writer")
def validateDefectTemplate(iid: str) -> Union[bool, Tuple[str, int]]:
    """
    Validate a defect template suggestion in the "pollenisator" database using its id. The suggestion is inserted as a defect
    The suggestion is removed

    Args:
        iid (str): The id of the defect template suggestion to be validated.

    Returns:
        Union[bool, Tuple[str, int]]: True if the operation was successful, otherwise a tuple containing an error message and status code.
    """
    dbclient = DBClient.getInstance()
    suggestion = dbclient.findInDb("pollenisator", "defectssuggestions", {"_id":ObjectId(iid)}, False)
    if suggestion is None:
        return "Not found", 404
    existing = dbclient.findInDb("pollenisator", "defects", {"$or":[{"_id":ObjectId(iid)}, {"title": suggestion.get("title")}]}, False)
    if existing is not None:
        suggestion["suggestion_type"] = "update"
        res = update("pollenisator", iid, True, suggestion)
    else:
        suggestion["suggestion_type"] = "insert"
        res = insert("pollenisator", suggestion)
        if not res["res"]:
            return res
    dbclient.deleteFromDb("pollenisator", "defectssuggestions", {"_id":ObjectId(iid)})
    return True

@permission("user")
def updateDefectTemplate(iid: str, body: Dict[str, Any], **kwargs: Dict[str, Any]) -> Union[bool, Tuple[str, int]]:
    """
    Update a defect template in the "pollenisator" database using its id. The "_id" field in the body is ignored.

    Args:
        iid (str): The id of the defect template to be updated.
        body (Dict[str, Any]): A dictionary containing the new defect template details.

    Returns:
        Union[bool, Tuple[str, int]]: True if the operation was successful, otherwise a tuple containing an error message 
        and status code.
    """
    is_suggestion = "admin" not in kwargs["token_info"]["scope"] and "template_writer" not in kwargs["token_info"]["scope"] or body.get("is_suggestion", False)
    res: Union[bool, Tuple[str, int]]
    if is_suggestion:
        res = update_template_suggestion(iid, body, kwargs["token_info"]["sub"])
    else:
        res = update("pollenisator", iid, True, body)
    return res

@permission("user")
def deleteDefectTemplate(iid: str, is_suggestion: bool=False, **kwargs) -> Union[int, Any]:
    """
    Delete a defect template from the "pollenisator" database using its id.

    Args:
        iid (str): The id of the defect template to be deleted.

    Returns:
        Union[int, Any]: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
    """

    has_no_right = ("admin" not in kwargs["token_info"]["scope"] and "template_writer" not in kwargs["token_info"]["scope"])
    if not is_suggestion and has_no_right:
        return 403, "Forbidden"
    if is_suggestion:
        return delete_template_suggestion(iid)
    if not has_no_right:
        return delete("pollenisator", iid)
    return 200, "Nothing happened"

def delete_template_suggestion(iid: str) -> int:
    """
    Delete a defect template suggestion from the "pollenisator" database using its id.

    Args:
        iid (str): The id of the defect template suggestion to be deleted.

    Returns:
        int: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
    """
    dbclient = DBClient.getInstance()
    return dbclient.deleteFromDb("pollenisator", "defectssuggestions", {"_id":ObjectId(iid)})

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
    defects = Defect.fetchObjects(pentest, {"_id": {"$in": iids_list}})
    ret: Dict[str, str] = {}
    if defects is None:
        return ret
    for defect_o in defects:
        defect_o = cast(Defect, defect_o)
        ret_str = defect_o.getTargetRepr()
        ret[str(defect_o.getId())] = ret_str
    return ret
