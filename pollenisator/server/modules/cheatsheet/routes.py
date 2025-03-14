"""
CheckItem in cheatsheet module,
routes for the checkitem object.
"""
from typing import Any, Dict, List, Tuple, Union, cast
from typing_extensions import TypedDict
from bson import ObjectId
import json

import pymongo
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.command import Command
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance, getTargetRepr
from pollenisator.server.permission import permission
from pollenisator.core.components.utils import JSONDecoder
import bson

CheckItemInsertResult = TypedDict('CheckItemInsertResult', {'res': bool, 'iid': ObjectId})
ErrorStatus = Tuple[str, int]

@permission("user")
def insert(body: Dict[str, Any]) -> Union[ErrorStatus, CheckItemInsertResult]:
    """
    Insert cheatsheet information.

    Args:
        body (Dict[str, Any]): The data to insert.

    Returns:
        CheckItemInsertResult: A dictionary with the result of the insertion.
    """
    try:
        body = json.loads(json.dumps(body), cls=JSONDecoder)
        defect_tags = body.get("defect_tags", [])
        if not isinstance(defect_tags, list):
            return "defect_tags must be a list", 400
        for defect_tag in defect_tags:
            if not isinstance(defect_tag, list):
                return "defect_tags must be a list of list", 400
            if not isinstance(defect_tag[0], str):
                return "defect_tags must be a list of list of 2 values : string, ObjectId", 400
            if not isinstance(defect_tag[1], ObjectId):
                if isinstance(defect_tag[1], str):
                    defect_tag[1] = ObjectId(defect_tag[1].replace("ObjectId|",""))
                else:
                    return "defect_tags must be a list of list of 2 values : string, ObjectId", 400
                
    except json.JSONDecodeError:
        return "Invalid JSON", 400
    except bson.errors.InvalidId:
        return "Invalid ObjectId  in defect_tags", 400
    body["defect_tags"] = defect_tags
    checkitem = CheckItem("pollenisator", body)
    res: CheckItemInsertResult = checkitem.addInDb()
    return res

@permission("user")
def delete(iid: str) -> Union[ErrorStatus, int]:
    """
    Delete a cheatsheet item.

    Args:
        iid (str): The id of the cheatsheet item to delete.

    Returns:
       int: Returns "Not found" and 404 if the item is not found, 0 if the deletion failed, or the result of the deletion operation.
    """
    existing = CheckItem.fetchObject("pollenisator", {"_id":ObjectId(iid)})
    if existing is None:
        return "Not found", 404
    return existing.deleteFromDb()

@permission("user")
def update(iid: str, body: Dict[str, Any]) -> Union[ErrorStatus, bool]:
    """
    Update a cheatsheet item.

    Args:
        iid (str): The id of the cheatsheet item to update.
        body (Dict[str, Any]): The data to update.

    Returns:
        Union[ErrorStatus, bool]: Returns "Not found" and 404 if the item is not found, or True if the update was successful.
    """
    # Check if the checkitem to update exists
    existing = CheckItem.fetchObject("pollenisator", {"_id": ObjectId(iid)})
    if existing is None:
        return "Not found", 404
    body = json.loads(json.dumps(body), cls=JSONDecoder)
    return existing.updateInDb(body)


@permission("user")
def find(body: Dict[str,Any]) -> Union[ErrorStatus, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Find checkitems in the database.

    Args:
        body (Dict[str,Any]): The body of the request. It should contain a pipeline for the search, and a boolean indicating whether to return many results.

    Returns:
        Union[ErrorStatus, List[Dict[str, Any]], Dict[str, Any]]: Returns a list of results if many is True, a single result if many is False, or ("Not found", 404) if no results are found.
    """
    pipeline = body.get("pipeline", {})
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    many = body.get("many", True)
    dbclient = DBClient.getInstance()
    results: Union[Dict[str, Any], List[Dict[str, Any]], None, pymongo.cursor.Cursor] = dbclient.findInDb("pollenisator", "checkitems", pipeline, many)
    if results is None:
        return [] if many else ("Not found", 404)
    if many:
        results = cast(List[Dict[str, Any]], results)
        return [x for x in results]
    if isinstance(results, pymongo.cursor.Cursor):
        results = list(results)
    return results

@permission("pentester")
def getChecksData(pentest: str) -> Union[ErrorStatus, List[Dict[str, Any]]]:
    """
    Get all the checks data for a pentest.

    Args:
        pentest (str): The name of the pentest.

    Returns:
        Union[ErrorStatus, List[Dict[str, Any]]]: Returns "Not found" and 404 if the pentest is not found, or a list of checks data.
    """
    checks = CheckItem.fetchObjects(pentest, {})
    if checks is None:
        return "Not found", 404
    checkinstances = CheckInstance.fetchObjects(pentest, {})
    if checkinstances is None:
        checkinstances = []
    checkinstances_iids = []
    checkinstances_list = []
    for checkinstance in checkinstances:
        checkinstances_iids.append(checkinstance._id)
        checkinstances_list.append(checkinstance)
    repres = getTargetRepr(pentest, checkinstances_iids)
    return_values = {}
    for check in checks:
        return_values[check._id] = check.getData()
        return_values[check._id]["checkinstances"] = []
    for checkinstance in checkinstances_list:
        inst_data = checkinstance.getData()
        inst_data["representation"] = repres.get(str(checkinstance.target_iid), return_values[checkinstance.check_iid]["title"])
        return_values[checkinstance.check_iid]["checkinstances"].append(inst_data)
    return sorted([x for x in return_values.values()], key=lambda x: x["priority"])


@permission("pentester")
def applyToPentest(pentest: str, iid: str, body: Dict[str, Any], **kwargs: Dict[str, Any]) -> Union[ErrorStatus, Dict[str, bool]]:
    """
    Apply a cheatsheet to a pentest.

    Args:
        pentest (str): The name of the pentest.
        iid (str): The id of the cheatsheet item.
        body (Dict[str, Any]): The body of the request.
        **kwargs (Dict[str, Any]): Additional keyword arguments.

    Returns:
        Union[ErrorStatus, Dict[str, bool]]: Returns "Not found" and 404 if the cheatsheet item is not found, or a dictionary with the result of the operation.
    """
    user = kwargs["token_info"]["sub"]
    check_item = CheckItem.fetchObject("pollenisator", {"_id":ObjectId(iid)})
    if check_item is None:
        return "Not found", 404
    for command in check_item.commands:
        pentest_equiv_command = Command.fetchObject(pentest, {"original_iid":str(command)})
        if pentest_equiv_command is None:
            orig = Command.fetchObject("pollenisator", {"_id":ObjectId(command)})
            if orig:
                mycommand =  orig.getData()
                mycommand["original_iid"] = str(mycommand["_id"])
                mycommand["_id"] = None
                mycommand["indb"] = pentest
                mycommand["owner"] = user
                Command(pentest, mycommand).addInDb()
    check_item.apply_retroactively(pentest)
    return {"res": True}
