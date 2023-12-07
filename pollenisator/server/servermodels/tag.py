from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.core.components.utils import JSONEncoder
from pollenisator.core.controllers.controllerelement import ControllerElement
from pollenisator.server.permission import permission

@permission("pentester")
def addTag(pentest, item_id, body):
    item_type = body.get("item_type", "")
    if item_type == "":
        return  "No item type given", 400
    item_class = ServerElement.classFactory(item_type)
    item = item_class.fetchObject(pentest, {"_id": ObjectId(item_id)})
    if item is None:
        return "Invalid item, not found", 404
    tag = body.get("tag", "")
    overrideGroups = body.get("overrideGroups", False)
    ControllerElement(item).addTag(tag, overrideGroups)
    return True
    

@permission("pentester")
def delTag(pentest, item_id, body):
    item_type = body.get("item_type", "")
    if item_type == "":
        return  "No item type given", 400
    item_class = ServerElement.classFactory(item_type)
    item = item_class.fetchObject(pentest, {"_id": ObjectId(item_id)})
    if item is None:
        return "Invalid item, not found", 404
    tag = body.get("tag", "")
    ControllerElement(item).delTag(tag)
    return True

@permission("pentester")
def setTags(pentest, item_id, body):
    item_type = body.get("item_type", "")
    if item_type == "":
        return  "No item type given", 400
    item_class = ServerElement.classFactory(item_type)
    item = item_class.fetchObject(pentest, {"_id": ObjectId(item_id)})
    if item is None:
        return "Invalid item, not found", 404
    tags = body.get("tags", [])
    ControllerElement(item).setTags(tags)
    return True

@permission("pentester")
def getTaggedBy(pentest, tag_name):
    dbclient = DBClient.getInstance()
    list_of_elems = {}
    tags = dbclient.findInDb(pentest, "tags", {"tags.name":tag_name}, multi=True)
    for tag in tags:
        list_of_elems[tag["item_type"]] = list_of_elems.get(tag["item_type"], []) + [tag["item_id"]]
    for item_type, item_ids in list_of_elems.items():
        list_of_elems[item_type] = [x for x in dbclient.findInDb(pentest, item_type, {"_id": {"$in": item_ids}}, multi=True)]
    
    return list_of_elems