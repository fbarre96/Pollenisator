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
from pollenisator.server.permission import permission
from pollenisator.core.components.utils import JSONDecoder

CheckItemInsertResult = TypedDict('CheckItemInsertResult', {'res': bool, 'iid': ObjectId})
ErrorStatus = Tuple[str, int]

@permission("user")
def insert(body: Dict[str, Any]) -> CheckItemInsertResult:
    """
    Insert cheatsheet information.

    Args:
        body (Dict[str, Any]): The data to insert.

    Returns:
        CheckItemInsertResult: A dictionary with the result of the insertion.
    """
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
    # Check if the title of the checkitem to update is the same as the one provided in the body
    checkitem = CheckItem("pollenisator", body)
    data = checkitem.getData()
    # Remove the type and _id from the body because they can't be updated
    if "type" in data:
        del data["type"]
    if "_id" in data:
        del data["_id"]
    # Update the checkitem
    dbclient = DBClient.getInstance()
    dbclient.updateInDb("pollenisator", CheckItem.coll_name, {"_id": ObjectId(iid), "type":"checkitem"}, {"$set": data}, False, True)
    return True


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
def applyToPentest(pentest: str, iid: str, _body: Dict[str, Any], **kwargs: Dict[str, Any]) -> Union[ErrorStatus, Dict[str, bool]]:
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
