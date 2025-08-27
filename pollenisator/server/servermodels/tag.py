"""
Handle  request common to Tags
"""
from typing import Dict, Any, List, Optional, Tuple, Union
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.element import Element
from pollenisator.server.permission import permission
from pollenisator.core.components.logger_config import logger

@permission("pentester")
def addTag(pentest: str, item_id: str, body: Dict[str, Any]) -> Union[Tuple[str, int], bool]:
    """
    Add a tag to an item in the database. The item type is fetched from the body of the request. If no item type is given, 
    an error message is returned. If the item does not exist, an error message is returned. Otherwise, the tag is added to 
    the item.

    Args:
        pentest (str): The name of the pentest.
        item_id (str): The id of the item to be tagged.
        body (Dict[str, Any]): A dictionary containing the tag details.

    Returns:
        Union[Tuple[str, int], bool]: An error message and status code if an error occurred, otherwise True.
    """
    item_type = body.get("item_type", "")
    if item_type == "":
        return  "No item type given", 400
    item_class = Element.classFactory(item_type)
    if item_class is None:
        return "Invalid item type", 400
    item = item_class.fetchObject(pentest, {"_id": ObjectId(item_id)})
    if item is None:
        return "Invalid item, not found", 404
    tag = body.get("tag", "")
    overrideGroups = body.get("overrideGroups", False)
    item.addTag(tag, overrideGroups)
    return True

@permission("pentester")
def delTag(pentest: str, item_id: str, body: Dict[str, Any]) -> Union[Tuple[str, int], bool]:
    """
    Delete a tag from an item in the database. The item type is fetched from the body of the request. If no item type is 
    given, an error message is returned. If the item does not exist, an error message is returned. Otherwise, the tag is 
    deleted from the item.

    Args:
        pentest (str): The name of the pentest.
        item_id (str): The id of the item from which the tag will be deleted.
        body (Dict[str, Any]): A dictionary containing the tag details.

    Returns:
        Union[Tuple[str, int], bool]: An error message and status code if an error occurred, otherwise True.
    """
    item_type = body.get("item_type", "")
    if item_type == "":
        return  "No item type given", 400
    item_class = Element.classFactory(item_type)
    if item_class is None:
        return "Invalid item type", 400
    item = item_class.fetchObject(pentest, {"_id": ObjectId(item_id)})
    if item is None:
        return "Invalid item, not found", 404
    tag = body.get("tag", "")
    item.delTag(tag)
    return True

@permission("pentester")
def setTags(pentest: str, item_id: str, body: Dict[str, Any]) -> Union[Tuple[str, int], bool]:
    """
    Set the tags of an item in the database. The item type is fetched from the body of the request. If no item type is 
    given, an error message is returned. If the item does not exist, an error message is returned. Otherwise, the tags of 
    the item are set to the given tags.

    Args:
        pentest (str): The name of the pentest.
        item_id (str): The id of the item whose tags will be set.
        body (Dict[str, Any]): A dictionary containing the tag details.

    Returns:
        Union[Tuple[str, int], bool]: An error message and status code if an error occurred, otherwise True.
    """
    item_type = body.get("item_type", "")
    if item_type == "":
        return  "No item type given", 400
    item_class = Element.classFactory(item_type)
    if item_class is None:
        return "Invalid item type", 400
    item = item_class.fetchObject(pentest, {"_id": ObjectId(item_id)})
    if item is None:
        return "Invalid item, not found", 404
    tags = body.get("tags", [])
    item.setTags(tags)
    return True

@permission("pentester")
def getTaggedBy(pentest: str, tag_name: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all items in the database that are tagged with a given tag. The items are grouped by their type.

    Args:
        pentest (str): The name of the pentest.
        tag_name (str): The name of the tag.

    Returns:
        Dict[str, List[Dict[str, Any]]]: A dictionary where the keys are the item types and the values are lists of items of that type.
    """
    dbclient = DBClient.getInstance()
    list_of_elems: Dict[str, List[Dict[str, Any]]] = {}
    tags = dbclient.findInDb(pentest, "tags", {"tags.name":tag_name}, multi=True)
    for tag in tags:
        list_of_elems[tag["item_type"]] = list_of_elems.get(tag["item_type"], []) + [tag["item_id"]]
    for item_type, item_ids in list_of_elems.items():
        list_of_elems[item_type] = [x for x in dbclient.findInDb(pentest, item_type, {"_id": {"$in": item_ids}}, multi=True)]
    return list_of_elems

@permission("pentester")
def getRegisteredTags(pentest: str) -> List[Dict[str, Any]]:
    """
    Get the list of all tags that are registered in the database.

    Args:
        pentest (str): The name of the pentest.

    Returns:
        List[str]: A list of all tags that are registered in the database.
    """
    dbclient = DBClient.getInstance()
    tags = dbclient.getRegisteredTags(pentest, only_name=False)
    return tags

@permission("pentester")
def getAllTagsWithTargetInfo(pentest: str, limit: Optional[int] = None , skip: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Get all tags in the database along with their target information.

    Args:
        pentest (str): The name of the pentest.
        limit (int, optional): The maximum number of tags to return. Defaults to None (no limit).
        skip (int, optional): The number of tags to skip. Defaults to 0.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries where each dictionary contains the tag name and its target information.
    """
    dbclient = DBClient.getInstance()
    tags = dbclient.findInDb(
        pentest,
        "tags",
        {"tags": {"$ne": []}},  # only fetch documents where tags array is not empty
        multi=True,
        limit=limit,
        skip=skip
    )
    if tags is None:
        return []
    tags = sorted(tags, key=lambda x: x["date"], reverse=True)
    tags_iids_per_types: Dict[str, List[str]] = {}
    for tag in tags:
        if tag["item_type"] not in tags_iids_per_types:
            tags_iids_per_types[tag["item_type"]] = []
        tags_iids_per_types[tag["item_type"]].append(tag["item_id"])
    items_per_type: Dict[str, Dict[str, Any]] = {}
    for item_type, item_ids in tags_iids_per_types.items():
        target_class = Element.classFactory(item_type)
        if target_class is None:
            logger.error("Invalid target type used : %s", item_type)
            continue
        items_objs = target_class.fetchObjects(pentest, {"_id": {"$in": [ObjectId(item_id) for item_id in item_ids]}})
        items_objs = [item for item in items_objs if item is not None]
        items_per_type[item_type] = {str(item.getId()): item.getDetailedString() for item in items_objs}
    for tag in tags:
        tag["item"] = items_per_type.get(tag["item_type"], {}).get(str(tag["item_id"]), "Unknown item")

    return tags