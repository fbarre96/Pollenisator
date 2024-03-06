"""
Handles all generic interactions with the database
"""
import json
from typing import Any, Dict, List, Set, Tuple, Union
import tempfile
import re
import shutil
import os
from lark import Tree
from bson import ObjectId
from flask import Response, send_file
import werkzeug
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.parser import Parser, ParseError, Term
from pollenisator.core.components.tag import Tag
from pollenisator.core.components.utils import JSONDecoder, getMainDir, isIp, JSONEncoder
from pollenisator.core.models.command import Command
from pollenisator.core.models.defect import Defect
from pollenisator.core.models.element import Element
from pollenisator.core.models.interval import Interval
from pollenisator.core.models.scope import Scope
from pollenisator.core.models.wave import Wave
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.permission import permission
from pollenisator.core.components.logger_config import logger

dbclient = DBClient.getInstance()

searchable_collections = set(["waves","scopes","ips","ports","tools","defects", "checkinstances", "commands", "computers","shares","users"])
validPollenisatorDbCollections = [ "checkitems", "commands", "settings" , "defects"]
operato_trans = {
    "||regex||":"$regex", "==":"$eq", "!=": "$ne", ">":"$gt", "<":"$lt", ">=":"$gte", "<=":"$lte", "in":"", "not in":"$nin"
}

ErrorStatus = Tuple[str, int]

def status() -> bool:
    """
    Return true if the database is connected
    
    Returns:
        bool: True if the database is connected
    """
    dbclient.connect()
    return dbclient.client is not None

def getVersion() -> str:
    """
    Return the current database version.

    Returns:
        str: The current database version.
    """
    version_key = dbclient.findInDb("pollenisator","infos",{"key":"version"}, False)
    if version_key is None:
        return "Unknown"
    return str(version_key["value"])

@permission("user")
def getUser(_pentest: str, **kwargs: Any) -> str:
    """
    Return the user associated with the token.

    Args:
        pentest (str): The name of the pentest.
        kwargs (Any): Additional keyword arguments.
    
    Returns:
        str: The user associated with the token.
    """
    return str(kwargs["token_info"]["sub"])

@permission("pentester")
def update(pentest: str, collection: str, body: Dict[str, Union[str, bool]]) -> ErrorStatus:
    """
    Update a collection in the database with the given pipeline and update pipeline.

    Args:
        pentest (str): The UUID of the pentest.
        collection (str): The name of the collection to update.
        body (Dict[str, Union[str, bool]]): A dictionary containing the pipeline, update pipeline, and additional parameters.
            "pipeline" (str): The pipeline to use for the update.
            "updatePipeline" (str): The update pipeline to use for the update.
            "many" (bool): Whether to update many documents.
            "notify" (bool): Whether to notify the user of the update.
            "upsert" (bool, optional): Whether to upsert the document.

    Returns:
        ErrorStatus: True if the update was successful, otherwise an error message and status code.
    """
    pipeline = body["pipeline"] if body["pipeline"] is not None else "{}"
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    updatePipeline = body["updatePipeline"]
    if isinstance(updatePipeline, str):
        updatePipeline = json.loads(updatePipeline, cls=JSONDecoder)
    if not isinstance(updatePipeline, dict):
        return "Update pipeline argument was not valid", 400
    if pentest == "pollenisator":
        if collection not in validPollenisatorDbCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in dbclient.listPentestUuids():
        return "Pentest argument is not a valid pollenisator pentest", 403

    dbclient.updateInDb(pentest, collection, pipeline, updatePipeline, body.get("many", False), body["notify"], body.get("upsert", False))
    return "Success", 200

@permission("pentester")
def insert(pentest: str, collection: str, body: Dict[str,Any]) -> ErrorStatus:
    """
    Insert a document into a collection in the database with the given pipeline.

    Args:
        pentest (str): The UUID of the pentest.
        collection (str): The name of the collection to insert into.
        body (Dict[str, Any]): A dictionary containing the pipeline and additional parameters.
            "pipeline" (str): The pipeline to use for the insertion.
            "parent" (str): The parent of the document to insert.
            "notify" (bool): Whether to notify the user of the insertion.

    Returns:
        ErrorStatus: The ID of the inserted document if the insertion was successful, otherwise an error message and status code.
    """
    pipeline = body["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    if pentest == "pollenisator":
        if collection not in validPollenisatorDbCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in dbclient.listPentestUuids():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = dbclient.insertInDb(pentest, collection, pipeline, body["parent"], body["notify"])
    return str(res.inserted_id), 200

@permission("pentester")
def find(pentest: str, collection: str, body: Dict[str, Any]) -> Union[Dict[str, Any], List[Dict[str, Any]], ErrorStatus]:
    """
    Find documents in a collection in the database with the given pipeline.

    Args:
        pentest (str): The UUID of the pentest.
        collection (str): The name of the collection to find in.
        body (Dict[str, Any]): A dictionary containing the pipeline and additional parameters.
            "pipeline" (str): The pipeline to use for the find operation.
            "many" (bool, optional): Whether to find many documents.
            "skip" (None, optional): The number of documents to skip.
            "limit" (None, optional): The maximum number of documents to return.
            "use_cache" (bool, optional): Whether to use the cache.

    Returns:
        Union[Dict[str, Any], List[Dict[str, Any]], ErrorStatus]: The found documents if the find operation was successful, otherwise an error message and status code.
    """
    pipeline = body["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    if pentest == "pollenisator":
        if collection not in validPollenisatorDbCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in dbclient.listPentestUuids():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = dbclient.findInDb(pentest, collection, pipeline, body.get("many", True), body.get("skip", None), body.get("limit", None), body.get("use_cache", True))
    if isinstance(res, dict):
        return res
    elif res is None:
        return "Not found", 404
    else:
        ret = []
        for r in res:
            r["_id"] = str(r["_id"])
            ret.append(r)
        return ret

@permission("pentester")
def search(pentest: str, s: str, textonly: bool) -> Union[Dict[str, List[Dict[str, Any]]], ErrorStatus]:
    """
    Use a parser to convert the search query into mongo queries and returns all matching objects.

    Args:
        pentest (str): The UUID of the pentest.
        s (str): The search query.
        textonly (bool): Whether to only search text fields.

    Returns:
        Union[Dict[str, List[Dict[str, Any]]], ErrorStatus]: A dictionary where each key is a collection name and each value is a list of matching documents if the search was successful, otherwise an error message and status code.
    """
    searchQuery = s
    if pentest not in dbclient.listPentestUuids():
        return "Pentest argument is not a valid pollenisator pentest", 400
    try:
        collections: Set[str] = set()
        if not textonly:
            parser = Parser(searchQuery)
            condition_list = parser.getResult()
            # Searching
            builtPipeline = _evaluateCondition(collections, condition_list)
            logger.debug("DEBUG : coll=%s pipeline=%s", collections, builtPipeline)
        if len(collections) == 0:
            collections = searchable_collections
        list_of_objects: Dict[str, Any] = {}
        for collection in collections:
            list_of_objects[collection] = []
            if textonly:
                elem = Element.classFactory(collection)
                if elem is None:
                    return f"Collection {collection} is not searchable", 400
                builtPipeline = elem.buildTextSearchQuery(searchQuery)

            if collection == "checkinstances":
                res = dbclient.findInDb("pollenisator", "checkitems", builtPipeline, True)
                for item in res:
                    checks = dbclient.findInDb(pentest, "checkinstances", {"check_iid":str(item.get("_id"))}, True)
                    for check_element in checks:
                        list_of_objects[collection].append(check_element)
            else:
                res = dbclient.findInDb(pentest, collection, builtPipeline, True)
            if res is None:
                continue
            for db_elem in res:
                list_of_objects[collection].append(db_elem)

        return list_of_objects
    except ParseError as e:
        return str(e).split("\n", maxsplit=1)[0], 400
    
def _evaluateCondition(searchable_collections_to_use: Set[str], condition_list: Union[Tree, Tuple[str, Union[bool, Term, List[Any]]], Tuple[Union[bool, Term, List[Any]],str, Union[bool, Term, List[Any]]]]) -> Dict[str, Any]:
    """
    Recursive function evaluating a given condition.

    Args:
        searchable_collections_to_use (Set[str]): The starting list of collection to search objects in.
        condition_list (Union[Tree, Tuple[str, Union[bool, Term, List[Any]]], Tuple[Union[bool, Term, List[Any]],str, Union[bool, Term, List[Any]]]]): A list of 2 or 3 elements representing a condition or a boolean value. 
            If 2 elements:
                0 is a unary operator and 1 is a bool value a term or a condition (as a list).
            If 3:
                0th and 2nd element are either a Term object, a value or a condition to compare the term against.
                1th element is a binary operator.

    Returns:
        Dict[str, Any]: The evaluated condition as a dictionary.

    Raises:
        Exception: If the condition_list is not a list, or if it contains an invalid number of elements, or if it contains an unknown operator.
    """
    currentCondition: Dict[str, Union[Tree, Tuple[str, Union[bool, Term, List[Any]]], Tuple[Union[bool, Term, List[Any]],str, Union[bool, Term, List[Any]]]]] = {}
    if not isinstance(condition_list, list):
        raise Exception(f"The evaluation of a condition was not given a condition but {str(type(condition_list))} was given")
    if len(condition_list) == 2:
        if condition_list[0] == "not":
            if isinstance(condition_list[1], list):
                currentCondition["$not"] = _evaluateCondition(searchable_collections_to_use, condition_list[1])
            else:
                raise Exception(f"Not operator expected a condition not {str(condition_list[1])}")
        else:
            raise Exception("Invalid condition with 2 elements and not a unary operator")
    elif len(condition_list) == 3:
        operator = condition_list[1]
        if operator in ["or", "and"]:
            currentCondition["$"+operator] = [_evaluateCondition(searchable_collections_to_use, condition_list[0]), _evaluateCondition(searchable_collections_to_use, condition_list[2])]
        elif operator in operato_trans.keys():
            if operator == "||regex||":
                termToSearch = str(condition_list[0])
                value = str(condition_list[2])
            else:
                termToSearch = condition_list[0] if isinstance(condition_list[0], Term) else condition_list[2]
                termToSearch = str(termToSearch)
                value = condition_list[2] if isinstance(condition_list[0], Term) else condition_list[0]
            if isinstance(value, str):
                if value.startswith("\"") and value.endswith("\""):
                    value = value[1:-1]
            if termToSearch == "type":
                if operator == "==":
                    if not value.endswith("s"):
                        value += "s"
                    searchable_collections_to_use.add(value)
                else:
                    raise Exception("When filtering type, only == is a valid operators")
            else:
                if operato_trans[operator] == "":
                    currentCondition[str(termToSearch)] = str(value)
                else:
                    currentCondition[str(termToSearch)] = {operato_trans[operator]: str(value)}
        else:
            raise Exception(f"Unknown operator {operator}")
    else:
        raise Exception(f"Invalid condition with {len(condition_list)} elements")
    return currentCondition

@permission("pentester")
def count(pentest: str, collection: str, body: Dict[str, Any]) -> Union[int, Tuple[str, int]]:
    """
    Count the number of documents in a collection in the database that match the given pipeline.

    Args:
        pentest (str): The UUID of the pentest.
        collection (str): The name of the collection to count in.
        body (Dict[str, Union[str, Dict[str, Any]]]): A dictionary containing the pipeline.
            "pipeline" (Union[str, Dict[str, Any]]): The pipeline to use for the count operation. If it is a string, it will be parsed as JSON.

    Returns:
        Union[int, Tuple[str, int]]: The count of matching documents if the count operation was successful, otherwise an error message and status code.
    """
    pipeline = body["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if pentest == "pollenisator":
        if collection not in validPollenisatorDbCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    elif pentest not in dbclient.listPentestUuids():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = dbclient.countInDb(pentest, collection, pipeline)
    return res

@permission("pentester")
def fetchNotifications(pentest: str, fromTime: str) -> List[Dict[str, Any]]:
    """
    Fetch notifications for a pentest from a given time.

    Args:
        pentest (str): The UUID of the pentest.
        fromTime (str): The time from which to fetch notifications as a string of the form "%Y-%m-%d %H:%M:%S.%f"".

    Returns:
        List[Dict[str, Any]]: A list of notifications. Each notification is a dictionary containing its details.
    """
    res = dbclient.fetchNotifications(pentest, fromTime)
    if res is None:
        return []
    return [n for n in res]

@permission("pentester")
def aggregate(pentest: str, collection: str, body: List[Dict[str, Any]]) -> Union[List[Dict[str, Any]], Tuple[str, int]]:
    """
    Perform an aggregation operation on a collection in the database.

    Args:
        pentest (str): The UUID of the pentest.
        collection (str): The name of the collection to aggregate.
        body (List[Dict[str, Any]]): A list of dictionaries representing the aggregation pipeline.

    Returns:
        Union[List[Dict[str, Any]], Tuple[str, int]]: A list of documents resulting from the aggregation if the operation was successful, otherwise an error message and status code.
    """
    ret = []
    if pentest == "pollenisator":
        if collection not in validPollenisatorDbCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in dbclient.listPentestUuids():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = dbclient.aggregateFromDb(pentest, collection, body)
    for r in res:
        ret.append(r)
    return ret

@permission("pentester")
def delete(pentest: str, collection: str, body: Dict[str, Any]) -> Union[int, None, Tuple[str, int]]:
    """
    Delete documents from a collection in the database that match the given pipeline.

    Args:
        pentest (str): The UUID of the pentest.
        collection (str): The name of the collection to delete from.
        body (Dict[str, Any]): A dictionary containing the pipeline and additional parameters.
            "pipeline" (str): The pipeline to use for the delete operation. If it is a string, it will be parsed as JSON.
            "many" (bool): Whether to delete many documents.
            "notify" (bool): Whether to notify the user of the deletion.

    Returns:
        Union[None, int, Tuple[str, int]]: None if the delete operation was unsuccessful, the deleted count if everything is fine, otherwise an error message and status code.
    """
    pipeline = body["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not a valid dictionnary", 400
    if pentest == "pollenisator":
        if collection not in validPollenisatorDbCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in dbclient.listPentestUuids():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = dbclient.deleteFromDb(pentest, collection, pipeline, body["many"], body["notify"])
    if res is None:
        return None
    else:
        return res

@permission("pentester")
def bulk_delete(pentest: str, body: Union[str, Dict[str, List[str]]]) -> Union[int, ErrorStatus]:
    """
    Delete multiple documents from various collections in the database.

    Args:
        pentest (str): The UUID of the pentest.
        body (Union[str, Dict[str, List[str]]]): A dictionary or a JSON string representing the documents to delete.
            Each key is a collection name and each value is a list of document IDs to delete from that collection.

    Returns:
        Union[int, ErrorStatus]: The number of documents deleted if the operation was successful, otherwise an error message and status code.
    """
    data = body
    if isinstance(data, str):
        data = json.loads(data, cls=JSONDecoder)
    if not isinstance(data, dict):
        return "body was not a valid dictionnary", 400
    if pentest == "pollenisator":
        return "Impossible to bulk delete in this database", 403
    elif pentest not in dbclient.listPentestUuids():
        return "Pentest argument is not a valid pollenisator pentest", 403
    deleted = 0
    for obj_type in data:
        for obj_id_str in data[obj_type]:
            if not isinstance(obj_id_str, ObjectId) and str(obj_id_str).startswith("ObjectId|"):
                obj_id = ObjectId(str(obj_id_str).split("ObjectId|")[1])
            else:
                obj_id = ObjectId(obj_id_str)
            res = dbclient.deleteFromDb(pentest, obj_type, {"_id": ObjectId(obj_id)}, False, True)
            if res is not None:
                deleted += res
    return deleted

@permission("user")
def bulk_delete_commands(body: Union[str, Dict[str, List[str]]], **kwargs: Dict[str, Any]) -> Union[int, ErrorStatus]:
    """
    Delete multiple commands from the database.

    Args:
        body (Union[str, Dict[str, List[str]]]): A dictionary or a JSON string representing the commands to delete.
            Each key is a command type and each value is a list of command IDs to delete.
        **kwargs (Dict[str, Any]): Additional keyword arguments. The "token_info" key should contain a dictionary with a "sub" key representing the user.

    Returns:
        Union[int, ErrorStatus]: The number of commands deleted if the operation was successful, otherwise an error message and status code.
    """
    #user = kwargs["token_info"]["sub"]
    data = body
    if isinstance(data, str):
        data = json.loads(data, cls=JSONDecoder)
    if not isinstance(data, dict):
        return "body was not a valid dictionnary", 400
    deleted = 0
    for obj_type in data:
        if obj_type != "commands":
            return "You can delete only commands", 403
        for obj_id_str in data[obj_type]:
            if not isinstance(obj_id_str, ObjectId):
                if obj_id_str.startswith("ObjectId|"):
                    obj_id = ObjectId(obj_id_str.split("ObjectId|")[1])
            else:
                obj_id = ObjectId(obj_id_str)
            res = dbclient.deleteFromDb("pollenisator", obj_type, {"_id": ObjectId(obj_id)}, False, True)
            if res is not None:
                deleted += res
    return deleted

@permission("user")
def listPentests(**kwargs: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    List all pentests for a user, or all pentests if the user is an admin.

    Args:
        **kwargs (Dict[str, Union[str, List[str]]]): Additional keyword arguments. The "token_info" key should contain a dictionary with a "sub" key representing the user and a "scope" key representing the user's scope.

    Returns:
        List[Dict[str, Any]]: A list of pentests. Each pentest is a dictionary containing its details.
    """
    username = kwargs["token_info"]["sub"]
    if "admin" in kwargs["token_info"]["scope"]:
        user_filter = None
    else:
        user_filter = username
    ret = dbclient.listPentests(user_filter)
    if ret:
        return ret
    else:
        return []

def deletePentestFiles(pentest: str) -> None:
    """
    Delete all files associated with a pentest.

    Args:
        pentest (str): The UUID of the pentest.

    Returns:
        None
    """
    local_path = os.path.join(getMainDir(), "files")
    proofspath = os.path.join(local_path, pentest, "proof")
    if os.path.isdir(proofspath):
        shutil.rmtree(proofspath)
    resultspath = os.path.join(local_path, pentest, "result")
    if os.path.isdir(resultspath):
        shutil.rmtree(resultspath)

@permission("user")
def deletePentest(pentest: str, **kwargs: Dict[str,Any]) -> ErrorStatus:
    """
    Delete a pentest and all associated data.

    Args:
        pentest (str): The UUID of the pentest.
        **kwargs (Dict[str, Union[str, List[str]]]): Additional keyword arguments. The "token_info" key should contain a dictionary with a "sub" key representing the user and a "scope" key representing the user's scope.

    Returns:
        ErrorStatus: A success message if the deletion was successful, otherwise an error message and status code.
    """
    username = kwargs["token_info"]["sub"]
    if username != dbclient.getPentestOwner(pentest) and "admin" not in kwargs["token_info"]["scope"]:
        return "Forbidden", 403
    ret = dbclient.doDeletePentest(pentest)
    if ret:
        deletePentestFiles(pentest)
        return "Successful deletion", 200
    else:
        return  "Unknown pentest", 404

@permission("user")
def registerPentest(pentest: str, body: Dict[str, Any], **kwargs: Dict[str, Any]) ->ErrorStatus:
    """
    Register a new pentest.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str,Any]): A dictionary containing the details of the pentest.
            "pentest_type" (str): The type of the pentest.
            "start_date" (datetime): The start date of the pentest.
            "end_date" (datetime): The end date of the pentest.
            "scope" (List[str]): The scope of the pentest.
            "settings" (Dict[str, Any]): The settings for the pentest.
            "pentesters" (List[str]): The pentesters for the pentest.
        **kwargs (Dict[str, Any]): Additional keyword arguments. The "token_info" key should contain a dictionary with a "sub" key representing the user.

    Returns:
        ErrorStatus: The UUID of the new pentest if the registration was successful, otherwise an error message and status code.
    """
    username = kwargs["token_info"]["sub"]
    ret, msg = dbclient.registerPentest(username, pentest, False, False)
    if ret:
        #token = connectToPentest(pentest, **kwargs)
        #kwargs["token_info"] = decode_token(token[0])
        uuid = msg
        msgerror, success = preparePentest(uuid, body["pentest_type"], body["start_date"], body["end_date"], body["scope"], body["settings"], body["pentesters"], username, **kwargs)
        if not success:
            return msgerror, 400
        return msg, 200
    else:
        return msg, 403

@permission("owner")
def editPentest(pentest: str, body: Dict[str, str], **kwargs: Dict[str, Any]) -> Union[Dict[str, str], Tuple[Dict[str, str], int]]:
    """
    Edit the name of a pentest.

    Args:
        pentest (str): The UUID of the pentest.
        body (Dict[str, str]): A dictionary containing the new name of the pentest.
            "pentest_name" (str): The new name of the pentest.
        **kwargs (Dict[str, Any]): Additional keyword arguments. The "token_info" key should contain a dictionary with a "sub" key representing the user.

    Returns:
        Union[Dict[str, str], Tuple[Dict[str, str], int]]: A success message if the name change was successful, otherwise an error message and status code.
    """
    pentest_name = body.get("pentest_name", "")
    res, msg = dbclient.editPentest(pentest, pentest_name)
    if not res:
        return {"message": msg, "error": "Invalid name"}, 403
    return {"message": "Pentest name changed"}, 200

@permission("pentester")
def getPentestInfo(pentest: str, **kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get information about a pentest.

    Args:
        pentest (str): The UUID of the pentest.
        **kwargs (Dict[str, Any]): Additional keyword arguments. Not used in this function.

    Returns:
        Dict[str, Any]: A dictionary containing information about the pentest.
            "defects_count" (int): The total number of defects.
            "defects_count_critical" (int): The number of critical defects.
            "defects_count_major" (int): The number of major defects.
            "defects_count_important" (int): The number of important defects.
            "defects_count_minor" (int): The number of minor defects.
            "autoscan_status" (bool): The status of the autoscan.
            "tagged" (List[Dict[str, Union[str, datetime, List[str]]]]): A list of tagged items. Each item is a dictionary containing its details.
            "hosts_count" (int): The number of hosts.
            "tools_done_count" (int): The number of tools that are done.
            "tools_count" (int): The total number of tools.
            "checks_done" (int): The number of checks that are done.
            "checks_total" (int): The total number of checks.
    """
    ret: Dict[str, Any] = {}
    ret["defects_count"] = dbclient.countInDb(pentest, "defects", {})
    ret["defects_count_critical"] = dbclient.countInDb(pentest, "defects", {"risk":"Critical"})
    ret["defects_count_major"] = dbclient.countInDb(pentest, "defects", {"risk":"Major"})
    ret["defects_count_important"] = dbclient.countInDb(pentest, "defects", {"risk":"Important"})
    ret["defects_count_minor"] = dbclient.countInDb(pentest, "defects", {"risk":"Minor"})
    ret["autoscan_status"] = dbclient.findInDb(pentest, "autoscan", {"special":True}, False)
    if ret["autoscan_status"] is None:
        ret["autoscan_status"] = False
    ret["tagged"] = []
    tag_cursor = dbclient.findInDb(pentest, "tags", {}, True)
    for tagged in tag_cursor:
        infos = {}
        infos["_id"] = str(tagged["_id"])
        infos["date"] = tagged.get("date", "")
        infos["tags"] = tagged.get("tags", [])
        class_element = Element.classFactory(tagged.get("item_type", ""))
        if class_element is not None:
            elem = class_element.fetchObject(pentest, {"_id":ObjectId(tagged.get("item_id"))})
            if elem is not None:
                infos["detailed_string"] = elem.getDetailedString()
            else:
                infos["detailed_string"] = "Target not found"
        else:
            infos["detailed_string"] = "Target not found"
        ret["tagged"].append(infos)
    ret["hosts_count"] = dbclient.countInDb(pentest, "ips")
    ret["tools_done_count"] = dbclient.countInDb(pentest, "tools", {"status":"done"})
    ret["tools_count"] = dbclient.countInDb(pentest, "tools", {})
    ret["checks_done"] = dbclient.countInDb(pentest, "checkinstances", {"status":"done"})
    ret["checks_total"] = dbclient.countInDb(pentest, "checkinstances", {})
    return ret

def preparePentest(pentest_uuid: str, pentest_type: str, start_date: str, end_date: str, scope: str, settings: Dict[str, Union[str, int]], pentesters: str, owner: str, **kwargs: Dict[str, Any]) -> ErrorStatus:
    """
    Initiate a pentest database with wizard info.

    Args:
        pentest_uuid (str): The pentest (pentest uuid).
        pentest_type (str): A pentest type chosen from settings pentest_types. Used to select commands that will be launched by default.
        start_date (str): A beginning date and time for the pentest.
        end_date (str): Ending date and time for the pentest.
        scope (str): A list of scope valid string (IP, network IP or host name).
        settings (Dict[str, Union[str, int]]): A dict of settings with keys:
            * "Add domains whose IP are in scope": if 1, will do a dns lookup on new domains and check if found IP is in scope.
            * "Add domains who have a parent domain in scope": if 1, will add a new domain if a parent domain is in scope.
            * "Add all domains found":  Unsafe. if 1, all new domains found by tools will be considered in scope.
        pentesters (str): A string of pentesters, separated by commas or newlines.
        owner (str): The owner of the pentest.
        **kwargs (Dict[str, Any]): Additional keyword arguments. This should include a "token_info" key with a dictionary containing a "sub" key with the user's information.

    Returns:
        ErrorStatus: A tuple containing a string message and a boolean indicating the success of the operation.
    """
    user = kwargs["token_info"]["sub"]
    dbclient.insertInDb(pentest_uuid, "settings", {"key":"pentest_type", "value":pentest_type}, notify=False)
    dbclient.insertInDb(pentest_uuid, "settings", {"key":"include_domains_with_ip_in_scope", "value": settings['Add domains whose IP are in scope'] == 1}, notify=False)
    dbclient.insertInDb(pentest_uuid, "settings", {"key":"include_domains_with_topdomain_in_scope", "value":settings["Add domains who have a parent domain in scope"] == 1}, notify=False)
    dbclient.insertInDb(pentest_uuid, "settings", {"key":"include_all_domains", "value":settings["Add all domains found"] == 1}, notify=False)
    dbclient.insertInDb(pentest_uuid, "settings", {"key":"client_name", "value":settings["client_name"]}, notify=False)
    dbclient.insertInDb(pentest_uuid, "settings", {"key":"mission_name", "value":settings["mission_name"]}, notify=False)
    dbclient.insertInDb(pentest_uuid, "settings", {"key":"lang", "value":settings["lang"]}, notify=False)
    dbclient.insertInDb(pentest_uuid, "settings", {"key":"autoscan_threads", "value":4}, notify=False)
    pentester_list = [x.strip() for x in pentesters.replace("\n",",").split(",")]
    pentester_list.insert(0, owner)
    dbclient.insertInDb(pentest_uuid, "settings", {"key":"pentesters", "value": pentester_list}, notify=False)
    Command.addUserCommandsToPentest(pentest_uuid, user)
    #addCheckInstancesToPentest(pentest, pentest_type)
    commands = Command.getList({}, pentest_uuid)
    if not commands:
        commands = []
    wave_o = Wave(pentest_uuid).initialize("Main", commands)
    wave_o.addInDb()
    interval_o = Interval(pentest_uuid).initialize(wave_o.wave, start_date, end_date)
    try:
        interval_o.addInDb()
    except ValueError as e:
        return str(e), False
    scope = scope.replace("https://", "").replace("http://","")
    scope_list = scope.replace("\n", ",").split(",")
    for scope_item in scope_list:
        if scope_item.strip() != "":
            if isIp(scope_item.strip()):
                scope_o = Scope(pentest_uuid, {"wave":"Main", "scope":scope_item.strip()+"/32"})
            else:
                scope_o = Scope(pentest_uuid, {"wave":"Main", "scope":scope_item.strip()})
            scope_o.addInDb()
    return "", True

@permission("user")
def getSettings() -> List[Dict[str, Any]]:
    """
    Retrieve all settings from the database.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, each representing a setting.
    """
    res = dbclient.findInDb("pollenisator", "settings", {}, True)
    if res is None:
        return []
    return [s for s in res]

@permission("user")
def getSetting(pipeline: Union[str, Dict[str, Any]]) -> Union[ErrorStatus, Dict[str, Any]]:
    """
    Retrieve a specific setting from the database.

    Args:
        pipeline (Union[str, Dict[str, Any]]): A pipeline to filter the settings. Can be a string or a dictionary.

    Returns:
        Union[ErrorStatus, Dict[str, Any]]: If the pipeline argument was not valid, returns an error message and status code. Otherwise, returns the setting.
    """
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    return dbclient.findInDb("pollenisator", "settings", pipeline, False)

@permission("admin")
def createSetting(body: Dict[str, Union[str, Any]]) -> bool:
    """
    Create a new setting in the database.

    Args:
        body (Dict[str, Union[str, Any]]): A dictionary containing the key and value of the setting.
            "key" (str): The key of the setting.
            "value" (Any): The value of the setting.

    Returns:
        bool: True if the setting was successfully created, False otherwise.
    """
    key = body['key']
    value = body["value"]
    res = dbclient.insertInDb("pollenisator", "settings", {"key":key, "value":value})
    if res:
        return True
    return False

@permission("user")
def updateSetting(body: Dict[str, Union[str, Any]]) -> bool:
    """
    Update a setting in the database.

    Args:
        body (Dict[str, Union[str, Any]]): A dictionary containing the key and new value of the setting.
            "key" (str): The key of the setting.
            "value" (Any): The new value of the setting.

    Returns:
        bool: True if the setting was successfully updated, False otherwise.
    """
    key = body['key']
    value = body["value"]
    dbclient.updateInDb("pollenisator", "settings", {
                    "key": key}, {"$set": {"value": value}})
    return True

@permission("pentester", "body.pentest")
def registerTag(body: Dict[str, Any]) -> bool:
    """
    Register a tag in the database.

    Args:
        body (Dict[str, Any]): A dictionary containing the details of the tag.
            "name" (str): The name of the tag.
            "color" (str): The color of the tag.
            "level" (str): The level of the tag.
            "pentest" (str): The UUID of the pentest.
    Returns:
        bool: True if the tag was successfully registered, False otherwise.
    """

    name = body["name"]
    color = body["color"]
    level = body["level"]
    pentest = body["pentest"]
    return dbclient.doRegisterTag(pentest, Tag(name, color, level))

@permission("pentester", "body.pentest")
def unregisterTag(body: Dict[str, Any]) -> Union[bool, ErrorStatus]:
    """
    Unregister a tag from the database.

    Args:
        body (Dict[str, Any]): A dictionary containing the details of the tag.
            "name" (str): The name of the tag.
            "pentest" (str): The UUID of the pentest.

    Returns:
        Union[bool, Tuple[str, int]]: True if the tag was successfully unregistered, otherwise an error message and status code.
    """
    name = body["name"]
    pentest = body.get("pentest", "pollenisator")
    if pentest == "pollenisator":
        tags = json.loads(dbclient.findInDb("pollenisator", "settings", {"key":"tags"}, False)["value"], cls=JSONDecoder)
        val = tags.pop(name, None)
        if val is None:
            return "Not found", 404
        dbclient.updateInDb("pollenisator", "settings", {"key":"tags"}, {"$set": {"value":json.dumps(tags,  cls=JSONEncoder)}}, many=False, notify=True)
    else:
        tags = dbclient.find("settings", {"key":"tags"}, False)
        if tags is None:
            return "Not found", 404
        else:
            tags = tags.get("value", {})
            val = tags.pop(name, None)
            if val is None:
                return "Not found",404
            dbclient.updateInDb(pentest, "settings", {"key":"tags"}, {"$set": {"value":tags}}, many=False, notify=True)
            dbclient.updateInDb(pentest, "tags", {"tags":name}, {"$pull": {"tags":name}}, notify=True)
    return True

@permission("pentester")
def updatePentestTag(pentest: str, body: Dict[str, Any]) -> ErrorStatus:
    """
    Update a tag in the database.

    Args:
        pentest (str): The pentest associated with the tag.
        body (Dict[str, Union[str, int]]): A dictionary containing the new details of the tag.
            "name" (str): The new name of the tag.
            "color" (str): The new color of the tag.
            "level" (int): The new level of the tag.

    Returns:
        ErrorStatus: If the tag was not found, returns an error message and status code. Otherwise, returns None.
    """
    name = body["name"]
    color = body["color"]
    level = body["level"]
    tags = dbclient.findInDb(pentest, "settings", {"key":"tags"}, False)
    if tags is None:
        return "Not found", 404
    else:
        tags = tags.get("value", {})
        if name not in tags:
            return  "Not found", 404
        tags[name] = {"color":color, "level":level}
        dbclient.updateInDb(pentest, "settings", {"key":"tags"}, {"$set": {"value":tags}}, many=False, notify=True)
    return "Success", 200

@permission("user")
def updateTag(body: Dict[str, Any]) -> Union[ErrorStatus, bool]:
    """
    Update a tag in the database.

    Args:
        body (Dict[str, Ant]): A dictionary containing the new details of the tag.
            "name" (str): The new name of the tag.
            "color" (str): The new color of the tag.
            "level" (int): The new level of the tag.

    Returns:
        Union[ErrorStatus, bool]: If the tag was not found, returns an error message and status code. Otherwise, returns True.
    """
    name = body["name"]
    color = body["color"]
    level = body["level"]
    tags = json.loads(dbclient.findInDb("pollenisator", "settings", {"key":"tags"}, False)["value"], cls=JSONDecoder)
    if name not in tags:
        return "Not found", 404
    tags[name] = {"color":color, "level":level}
    dbclient.updateInDb("pollenisator", "settings", {"key":"tags"}, {"$set": {"value":json.dumps(tags,  cls=JSONEncoder)}}, many=False, notify=True)
    return True

@permission("pentester", "dbName")
def dumpDb(dbName: str, collection: str = "") -> Union[ErrorStatus, Response]:
    """
    Export a database dump into the exports/ folder as a gzip archive.
    It uses the mongodump utility installed with mongodb-org-tools.

    Args:
        dbName (str): The database name to dump.
        collection (str, optional): The collection to dump. Defaults to "".

    Returns:
        Union[ErrorStatus, Response]: If the database or collection was not found, or if the export failed, returns an error message and status code. Otherwise, returns the file to be downloaded.
    """
    if dbName != "pollenisator" and dbName not in dbclient.listPentestUuids():
        return "Database not found", 404
    if dbclient.db is None:
        dbclient.connect()
    if dbclient.db is None:
        return "Connection to database failed", 503
    collections = dbclient.db.list_collection_names()
    if collection != "" and collection not in collections:
        return "Collection not found in database provided", 404
    if collection != "" and not re.match(r"^[a-zA-Z0-9_\-]+$", collection):
        return "Invalid collection name", 400
    path = dbclient.dumpDb(dbName, collection)
    if not os.path.isfile(path):
        return "Failed to export database", 503
    try:
        return send_file(path, mimetype="application/gzip", attachment_filename=os.path.basename(path))
    except TypeError as _e: # python3.10.6 breaks https://stackoverflow.com/questions/73276384/getting-an-error-attachment-filename-does-not-exist-in-my-docker-environment
        return send_file(path, mimetype="application/gzip", download_name=os.path.basename(path))

@permission("user")
def importDb(orig_name: str, upfile: werkzeug.datastructures.FileStorage, **kwargs: Dict[str,Any]) -> ErrorStatus:
    """
    Import a database dump from a file.

    Args:
        orig_name (str): The original name of the database.
        upfile (Any): The file containing the database dump.
        **kwargs (Dict[str, Dict[str, str]]): Additional keyword arguments. The "token_info" key should contain a dictionary with a "sub" key representing the user.

    Returns:
        ErrorStatus: A message and status code indicating success or error.
    """
    username = kwargs["token_info"]["sub"]
    if upfile.filename is None:
        return "Invalid filename", 400
    dirpath = tempfile.mkdtemp()
    tmpfile = os.path.join(dirpath, os.path.basename(upfile.filename))
    with open(tmpfile, "wb") as f:
        f.write(upfile.stream.read())
    
    filename = os.path.basename(upfile.filename)
    filename = os.path.splitext(filename)[0]
    success = dbclient.importDatabase(username, tmpfile, orig_name, filename)
    shutil.rmtree(dirpath)
    return success

def doImportCommands(data: str, user: str) -> Union[ErrorStatus, List[Dict[str, Any]]]:
    """
    Import commands from a JSON string.

    Args:
        data (str): The JSON string containing the commands.
        user (str): The user performing the import.

    Returns:
        List[Dict[str, Any]]: A list of commands that failed to import.
    """
    try:
        commands = json.loads(data, cls=JSONDecoder)
    except:
        return "Invalid file format, json expected", 400
    if not isinstance(commands, dict):
        return "Invalid file format, object expected", 400
    if "commands" not in commands.keys():
        return "Invalid file format, object expected property: commands", 400
    if not isinstance(commands["commands"], list):
        return "Invalid file format, commands  properties must be lists", 400
    matchings = {}
    failed = []
    for command in commands["commands"]:
        save_id = str(command["_id"])
        del command["_id"]
        command["owners"] = command.get("owners", []) + [user]
        command_o = Command("pollenisator", command)
        obj_ins = command_o.addInDb()
        if obj_ins["res"]:
            matchings[save_id] = str(obj_ins["iid"])
        else:
            failed.append(command)
    return failed

def doImportCheatsheet(data: str, user: str) -> Union[ErrorStatus, List[Dict[str, Any]]]:
    """
    Import a cheatsheet from a JSON string.

    Args:
        data (str): The JSON string containing the cheatsheet.
        user (str): The user performing the import.

    Returns:
        Union[ErrorStatus, List[Dict[str, Any]]]: If the import was unsuccessful, returns an error message and status code. Otherwise, returns a list of items that failed to import.
    """
    try:
        checks = json.loads(data, cls=JSONDecoder)
    except:
        return "Invalid file format, json expected", 400
    if not isinstance(checks, dict):
        return "Invalid file format, object expected", 400
    if "checkitems" not in checks.keys():
        return "Invalid file format, object expected property: checkitems", 400
    if not isinstance(checks["checkitems"], list):
        return "Invalid file format, checkitems  properties must be lists", 400
    matching_commands = {}
    matching_defects = {}
    failed = []
    if "commands" not in checks.keys():
        return "Invalid file format, object expected property: commands", 400
    if not isinstance(checks["commands"], list):
        return "Invalid file format, commands  properties must be lists", 400
    if "defects" not in checks.keys():
        return "Invalid file format, object expected property: defects", 400
    if not isinstance(checks["defects"], list):
        return "Invalid file format, defects  properties must be lists", 400
    for command in checks["commands"]:
        save_id = str(command["_id"])
        del command["_id"]
        command_o = Command("pollenisator", command)
        obj_ins = command_o.addInDb()
        command_o.addOwner(user)
        matching_commands[save_id] = str(obj_ins["iid"])
        if not obj_ins["res"]:
            failed.append(command)
    for defect in checks["defects"]:
        save_id = str(defect["_id"])
        del defect["_id"]
        try:
            obj_ins = Defect("pollenisator", defect).addInDb()
            matching_defects[save_id] = str(obj_ins["iid"])
            if not obj_ins["res"]:
                failed.append(defect)
        except ValueError as _e:
            failed.append(defect)
    for check in checks["checkitems"]:
        save_id = str(check["_id"])
        del check["_id"]
        check_commands = check.get("commands", [])
        check_defects = check.get("defects", [])
        check_defect_tags = check.get("defect_tags", [])
        check["commands"] = []
        for command in check_commands:
            if str(command) in matching_commands:
                check["commands"].append(matching_commands[str(command)])
        check["defects"] = []
        for defect in check_defects:
            if str(defect) in matching_defects:
                check["defects"].append(matching_defects[str(defect)])
        defect_tags = []
        for defect_tag in check_defect_tags:
            if str(defect_tag[1]) in matching_defects:
                defect_tag[1] = str(matching_defects[str(defect_tag[1])])
                defect_tags.append(defect_tag)
        check["defect_tags"] = defect_tags
        check_o = CheckItem("pollenisator", check)
        check_o.addInDb()
    return failed

@permission("user")
def importCommands(upfile: werkzeug.datastructures.FileStorage, **kwargs: Dict[str, Any]) -> Union[ErrorStatus, List[Dict[str, Any]]]:
    """
    Import commands from a file.

    Args:
        upfile (werkzeug.datastructures.FileStorage): The file containing the commands.
        **kwargs (Dict[str, Dict[str, str]]): Additional keyword arguments. The "token_info" key should contain a dictionary with a "sub" key representing the user.

    Returns:
        Union[ErrorStatus, List[Dict[str, Any]]]: A list of commands that failed to import.
    """
    user = kwargs["token_info"]["sub"]
    data = upfile.stream.read()
    if isinstance(data, bytes):
        data_str = data.decode("utf-8")
    else:
        data_str = str(data)
    return doImportCommands(data_str, user)

@permission("user")
def importCheatsheet(upfile: werkzeug.datastructures.FileStorage, **kwargs: Dict[str, Any]) -> Union[ErrorStatus, List[Dict[str, Any]]]:
    """
    Import commands from a file.

    Args:
        upfile (werkzeug.datastructures.FileStorage): The file containing the commands.
        **kwargs (Dict[str, Dict[str, str]]): Additional keyword arguments. The "token_info" key should contain a dictionary with a "sub" key representing the user.

    Returns:
        Union[ErrorStatus, List[Dict[str, Any]]]: A list of commands that failed to import.
    """
    user = kwargs["token_info"]["sub"]
    data = upfile.stream.read()
    if isinstance(data, bytes):
        data_str = data.decode("utf-8")
    else:
        data_str = str(data)
    return doImportCheatsheet(data_str, user)

def doExportCommands() -> Dict[str, List[Dict[str, Any]]]:
    """
    Export all commands from the database.

    Returns:
        Dict[str, List[Dict[str, Any]]]: A dictionary with a "commands" key containing a list of all commands in the database.
    """
    res: Dict[str, List[Dict[str, Any]]] = {"commands":[]}
    commands = dbclient.findInDb("pollenisator", "commands", {}, True)
    for command in commands:
        c = command
        del c["owners"]
        if "users" in c:
            del c["users"]
        res["commands"].append(c)
    return res

def doExportCheatsheet() -> Dict[str, List[Dict[str, Any]]]:
    """
    Export all checkitems, defects, and commands from the database.

    Returns:
        Dict[str, List[Dict[str, Any]]]: A dictionary with "checkitems", "defects", and "commands" keys each containing a list of all items in the respective collections in the database.
    """
    res: Dict[str, List[Dict[str, Any]]] = {"checkitems":[], "commands":[], "defects":[]}
    checks = dbclient.findInDb("pollenisator", "checkitems", {}, True)
    for check in checks:
        c = check
        res["checkitems"].append(c)
    defects = dbclient.findInDb("pollenisator", "defects", {}, True)
    for defect in defects:
        c = defect
        res["defects"].append(c)
    commands = dbclient.findInDb("pollenisator", "commands", {}, True)
    for command in commands:
        c = command
        del c["owners"]
        if "users" in c:
            del c["users"]
        res["commands"].append(c)
    return res

@permission("user")
def exportCommands(**kwargs) -> Dict[str, List[Dict[str, Any]]]:
    """
    Export all commands from the database.

    Returns:
        Dict[str, List[Dict[str, Any]]]: A dictionary with a "commands" key containing a list of all commands in the database.
    """
    return doExportCommands()

@permission("user")
def exportCheatsheet(**kwargs) -> Dict[str, List[Dict[str, Any]]]:
    """
    Export all checkitems, defects, and commands from the database.

    Returns:
        Dict[str, List[Dict[str, Any]]]: A dictionary with "checkitems", "defects", and "commands" keys each containing a list of all items in the respective collections in the database.
    """
    return doExportCheatsheet()

@permission("pentester", "body.fromDb")
def copyDb(body: Dict[str, str]) -> Any:
    """
    Copy a database to another database.

    Args:
        body (Dict[str, str]): A dictionary containing the names of the source and destination databases.
            "toDb" (str): The name of the destination database.
            "fromDb" (str): The name of the source database.

    Returns:
        Any: The result of the database operation.
    """
    toCopyName = body["toDb"]
    fromCopyName = body["fromDb"]
    return dbclient.copyDb(fromCopyName, toCopyName)
