import json
import logging
import os
from bson import ObjectId
from flask import send_file
import tempfile
import re
import shutil
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Components.parser import Parser, ParseError, Term
from pollenisator.core.Components.Utils import JSONDecoder, getMainDir, isIp, JSONEncoder
from pollenisator.core.Controllers.WaveController import WaveController
from pollenisator.core.Controllers.IntervalController import IntervalController
from pollenisator.server.modules.Cheatsheet.checkinstance import addCheckInstancesToPentest
from pollenisator.server.ServerModels.Command import ServerCommand, addUserCommandsToPentest, doInsert as command_insert
from pollenisator.server.ServerModels.CommandGroup import addUserGroupCommandsToPentest, doInsert as command_group_insert
from pollenisator.server.ServerModels.Wave import ServerWave, insert as insert_wave
from pollenisator.server.ServerModels.Interval import ServerInterval, insert as insert_interval
from pollenisator.server.ServerModels.Scope import insert as insert_scope
from pollenisator.server.permission import permission
mongoInstance = MongoCalendar.getInstance()

searchable_collections = ["waves","scopes","ips","ports","tools","defects"]
validCollections = ["group_commands", "cheatsheet", "commands", "settings"]
operato_trans = {
    "||regex||":"$regex", "==":"$eq", "!=": "$ne", ">":"$gt", "<":"$lt", ">=":"$gte", "<=":"$lte", "in":"$in", "not in":"$nin"
    }

def status():
    mongoInstance.connect()
    return mongoInstance.client != None

def getVersion():
    # TODO : return connexion openapi version instead
    return "1.5.0"

@permission("user")
def getUser(pentest, **kwargs):
    return kwargs["token_info"]["sub"]

@permission("pentester")
def update(pentest, collection, body):
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
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendarNames():
        return "Pentest argument is not a valid pollenisator pentest", 403
    
    mongoInstance.updateInDb(pentest, collection, pipeline, updatePipeline, body["many"], body["notify"], body.get("upsert", False))
    return True

@permission("pentester")
def insert(pentest, collection, body):
    pipeline = body["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendarNames():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.insertInDb(pentest, collection, pipeline, body["parent"], body["notify"])
    return str(res.inserted_id)

@permission("pentester")
def find(pentest, collection, body):
    pipeline = body["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendarNames():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.findInDb(pentest, collection, pipeline, body.get("many", True), body.get("skip", None), body.get("limit", None))
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
def search(pentest, s):
    """Use a parser to convert the search query into mongo queries and returns all matching objects
    """
    searchQuery = s
    if pentest not in mongoInstance.listCalendarNames():
        return "Pentest argument is not a valid pollenisator pentest", 400
    try:
        parser = Parser(searchQuery)
        condition_list = parser.getResult()
        # Searching
        collections = []
        builtPipeline = _evaluateCondition(collections, condition_list)
        logging.debug(f"DEBUG : coll={collections} pipeline={builtPipeline}")
        if len(collections) == 0:
            collections = searchable_collections
        list_of_objects = {}
        for collection in collections:
            list_of_objects[collection] = []
            res = mongoInstance.findInDb(pentest, collection, builtPipeline, True)
            if res is None:
                continue
            for elem in res:
                list_of_objects[collection].append(elem)
        return list_of_objects
    except ParseError as e:
        return str(e).split("\n")[0], 400

def _evaluateCondition(searchable_collections, condition_list):
    """Recursive function evaluating a given condition.
    Args:
        searchable_collections: the starting list of collection to search objects in
        condition: a list of 2 or 3 elements representing a condition or a boolean value. 
            If 2 elements:
                0 is a unary operator and 1 is a bool value a term or a condition (as a list)
            If 3:
                0th and 2nd element are either a Term object, a value or a condition to compare the term against
                1th element is a binary operator

    Example:
    [[<core.Components.parser.Term object at 0x7f05ba85f910>, '==', '"port"'], 'and', [[<core.Components.parser.Term object at 0x7f05ba85f730>, '==', '"43"'], 'or', [<core.Components.parser.Term object at 0x7f05b9844280>, '==', '"44"']]]
    becomes
    searchable_collections = ["ports"], builtPipeline = {"$or":[{"port":"43"}, {"port":44}]}
    """
    currentCondition = {}
    if not isinstance(condition_list, list):
        raise Exception(f"The evaluation of a condition was not given a condition but {str(type(condition_list))} was given")
    if len(condition_list) == 2:
        if condition_list[0] == "not":
            if isinstance(condition_list[1], list):
                currentCondition["$not"] = _evaluateCondition(searchable_collections, condition_list[1]) 
            else:
                raise Exception(f"Not operator expected a condition not {str(condition_list[1])}")
        else:
            raise Exception("Invalid condition with 2 elements and not a unary operator")
    elif len(condition_list) == 3:
        operator = condition_list[1]
        if operator in ["or", "and"]:
            currentCondition["$"+operator] = [_evaluateCondition(searchable_collections, condition_list[0]), _evaluateCondition(searchable_collections, condition_list[2])]
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
                    searchable_collections.append(value)
                else:
                    raise Exception(f"When filtering type, only == is a valid operators")
            else:
                currentCondition[str(termToSearch)] = {operato_trans[operator]: str(value)}
        else:
            raise Exception(f"Unknown operator {operator}")
    else:
        raise Exception(f"Invalid condition with {len(condition_list)} elements")
    return currentCondition

@permission("pentester")
def count(pentest, collection, body):
    pipeline = body["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    elif pentest not in mongoInstance.listCalendarNames():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.countInDb(pentest, collection, pipeline)
    return res

@permission("pentester")
def fetchNotifications(pentest, fromTime):
    res = mongoInstance.fetchNotifications(pentest, fromTime)
    if res is None:
        return []
    return [n for n in res]

@permission("pentester")
def aggregate(pentest, collection, body):
    ret = []
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendarNames():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.aggregateFromDb(pentest, collection, body)
    for r in res:
        ret.append(r)
    return ret

@permission("pentester")
def delete(pentest, collection, body):
    pipeline = body["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not a valid dictionnary", 400
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendarNames():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.deleteFromDb(pentest, collection, pipeline, body["many"], body["notify"])
    if res is None:
        return
    else:
        return res.deleted_count

@permission("pentester")
def bulk_delete(pentest, body):
    data = body
    if isinstance(data, str):
        data = json.loads(data, cls=JSONDecoder)
    if not isinstance(data, dict):
        return "body was not a valid dictionnary", 400
    if pentest == "pollenisator":
        return "Impossible to bulk delete in this database", 403
    elif pentest not in mongoInstance.listCalendarNames():
        return "Pentest argument is not a valid pollenisator pentest", 403
    deleted = 0
    for obj_type in data:
        for obj_id in data[obj_type]:
            if not isinstance(obj_id, ObjectId):
                if obj_id.startswith("ObjectId|"):
                    obj_id = ObjectId(obj_id.split("ObjectId|")[1])
            res = mongoInstance.deleteFromDb(pentest, obj_type, {"_id": ObjectId(obj_id)}, False, True)
            if res is not None:
                deleted += res.deleted_count
    return deleted

@permission("user")
def bulk_delete_commands(body, **kwargs):
    user = kwargs["token_info"]["sub"]
    data = body
    if isinstance(data, str):
        data = json.loads(data, cls=JSONDecoder)
    if not isinstance(data, dict):
        return "body was not a valid dictionnary", 400
    deleted = 0
    for obj_type in data:
        if obj_type != "commands" and obj_type != "group_commands":
            return "You can delete only commands and group_commands", 403
        for obj_id in data[obj_type]:
            if not isinstance(obj_id, ObjectId):
                if obj_id.startswith("ObjectId|"):
                    obj_id = ObjectId(obj_id.split("ObjectId|")[1])
            res = mongoInstance.deleteFromDb("pollenisator", obj_type, {"_id": ObjectId(obj_id)}, False, True)
            if res is not None:
                deleted += res.deleted_count
    return deleted

@permission("user")
def listPentests(**kwargs):
    username = kwargs["token_info"]["sub"]
    if "admin" in kwargs["token_info"]["scope"]:
        username = None
    ret = mongoInstance.listCalendars(username)
    if ret:
        return ret
    else:
        return []

def deletePentestFiles(pentest):
    mongoInstance = MongoCalendar.getInstance()
    local_path = os.path.join(getMainDir(), "files")
    proofspath = os.path.join(local_path, pentest, "proof")
    if os.path.isdir(proofspath):
        shutil.rmtree(proofspath)
    resultspath = os.path.join(local_path, pentest, "result")
    if os.path.isdir(resultspath):
        shutil.rmtree(resultspath)

@permission("user")
def deletePentest(pentest, **kwargs):
    username = kwargs["token_info"]["sub"]
    if username != mongoInstance.getPentestOwner(pentest) and "admin" not in kwargs["token_info"]["scope"]:
        return "Forbidden", 403
    ret = mongoInstance.doDeleteCalendar(pentest)
    if ret:
        deletePentestFiles(pentest)
        return "Successful deletion"
    else:
        return  "Unknown pentest", 404

@permission("user")
def registerCalendar(pentest, body, **kwargs):
    username = kwargs["token_info"]["sub"]
    ret, msg = mongoInstance.registerCalendar(username, pentest, False, False)
    
    if ret:
        #token = connectToPentest(pentest, **kwargs)
        #kwargs["token_info"] = decode_token(token[0])
        prepareCalendar(pentest, body["pentest_type"], body["start_date"], body["end_date"], body["scope"], body["settings"], body["pentesters"], username, **kwargs)
        return msg
    else:
        return msg, 403

def prepareCalendar(dbName, pentest_type, start_date, end_date, scope, settings, pentesters, owner, **kwargs):
    """
    Initiate a pentest database with wizard info
    Args:
        dbName: the database name
        pentest_type: a pentest type choosen from settings pentest_types. Used to select commands that will be launched by default
        start_date: a begining date and time for the pentest
        end_date: ending date and time for the pentest
        scope: a list of scope valid string (IP, network IP or host name)
        settings: a dict of settings with keys:
            * "Add domains whose IP are in scope": if 1, will do a dns lookup on new domains and check if found IP is in scope
            * "Add domains who have a parent domain in scope": if 1, will add a new domain if a parent domain is in scope
            * "Add all domains found":  Unsafe. if 1, all new domains found by tools will be considered in scope.
    """
    user = kwargs["token_info"]["sub"]
    mongoInstance = MongoCalendar.getInstance()

    addUserCommandsToPentest(dbName, user)  
    addUserGroupCommandsToPentest(dbName, user)
    addCheckInstancesToPentest(dbName, pentest_type)
    # Duplicate all commands in local database
    # allcommands = ServerCommand.fetchObjects({})
    # for command in allcommands:
    #     command.indb = dbName
    #     insert_command(command.indb, CommandController(command).getData(), **kwargs)
    commands = ServerCommand.getList({"$or":[{"types": re.compile(pentest_type, re.IGNORECASE)}, {"types":"Commun"}]}, targetdb=dbName)
    if not commands:
        commands = []
    wave_o = ServerWave(dbName).initialize(dbName, commands)
    result_wave = insert_wave(dbName, WaveController(wave_o).getData())
    interval_o = ServerInterval(dbName).initialize(dbName, start_date, end_date)
    insert_interval(dbName, IntervalController(interval_o).getData())
    scope = scope.replace("https://", "").replace("http://","")
    scope = scope.replace("\n", ",").split(",")
    for scope_item in scope:
        if scope_item.strip() != "":
            if isIp(scope_item.strip()):
                insert_scope(dbName, {"wave":dbName, "scope":scope_item.strip()+"/32"})
            else:
                insert_scope(dbName, {"wave":dbName, "scope":scope_item.strip()})
    mongoInstance.insertInDb(dbName, "settings", {"key":"pentest_type", "value":pentest_type}, notify=False)
    mongoInstance.insertInDb(dbName, "settings", {"key":"include_domains_with_ip_in_scope", "value": settings['Add domains whose IP are in scope'] == 1}, notify=False)
    mongoInstance.insertInDb(dbName, "settings", {"key":"include_domains_with_topdomain_in_scope", "value":settings["Add domains who have a parent domain in scope"] == 1}, notify=False)
    mongoInstance.insertInDb(dbName, "settings", {"key":"include_all_domains", "value":settings["Add all domains found"] == 1}, notify=False)
    pentester_list = list(map(lambda x: x.strip(), pentesters.replace("\n",",").split(",")))
    pentester_list.insert(0, owner)
    mongoInstance.insertInDb(dbName, "settings", {"key":"pentesters", "value": pentester_list}, notify=False)

@permission("user")
def getSettings():
    res = mongoInstance.findInDb("pollenisator", "settings", {}, True)
    if res is None:
        return []
    return [s for s in res]

@permission("user")
def getSetting(pipeline):
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    return mongoInstance.findInDb("pollenisator", "settings", pipeline, False)

@permission("admin")
def createSetting(body):
    key = body['key']
    value = body["value"]
    res = mongoInstance.insertInDb("pollenisator", "settings", {"key":key, "value":value})
    if res:
        return True
    return False

@permission("user")    
def updateSetting(body):
    key = body['key']
    value = body["value"]
    mongoInstance.updateInDb("pollenisator", "settings", {
                    "key": key}, {"$set": {"value": value}})
    return True



@permission("pentester", "body.pentest")
def registerTag(pentest, body):
    name = body["name"]
    color = body["color"]
    return mongoInstance.doRegisterTag(pentest, name, color)

@permission("pentester", "body.pentest")
def unregisterTag(body):
    name = body["name"]
    pentest = body.get("pentest", "pollenisator")
    if pentest == "pollenisator":
        tags = json.loads(mongoInstance.findInDb("pollenisator", "settings", {"key":"tags"}, False)["value"], cls=JSONDecoder)
        val = tags.pop(name, None)
        if val is None:
            return 404, "Not found"
        mongoInstance.updateInDb("pollenisator", "settings", {"key":"tags"}, {"$set": {"value":json.dumps(tags,  cls=JSONEncoder)}}, many=False, notify=True)
    else:
        tags = mongoInstance.find("settings", {"key":"tags"}, False)
        if tags is None:
            return 404, "Not found"
        else:
            tags = tags.get("value", {})
            val = tags.pop(name, None)
            if val is None:
                return 404, "Not found"
            mongoInstance.updateInDb(pentest, "settings", {"key":"tags"}, {"$set": {"value":tags}}, many=False, notify=True)
            mongoInstance.updateInDb(pentest, "scopes", {"tags":name}, {"$pull": {"tags":name}}, notify=True)
            mongoInstance.updateInDb(pentest, "ips", {"tags":name}, {"$pull": {"tags":name}}, notify=True)
            mongoInstance.updateInDb(pentest, "ports", {"tags":name}, {"$pull": {"tags":name}}, notify=True)
            mongoInstance.updateInDb(pentest, "tools", {"tags":name}, {"$pull": {"tags":name}}, notify=True)
    return True

@permission("pentester")
def updatePentestTag(pentest, body):
    name = body["name"]
    color = body["color"]
    
    tags = mongoInstance.findInDb(pentest, "settings", {"key":"tags"}, False)
    if tags is None:
        return "Not found", 404
    else:
        tags = tags.get("value", {})
        if name not in tags:
            return  "Not found", 404
        tags[name] = color
        mongoInstance.updateInDb(pentest, "settings", {"key":"tags"}, {"$set": {"value":tags}}, many=False, notify=True)

@permission("user")
def updateTag(body):
    name = body["name"]
    color = body["color"]
    tags = json.loads(mongoInstance.findInDb("pollenisator", "settings", {"key":"tags"}, False)["value"], cls=JSONDecoder)
    if name not in tags:
        return "Not found", 404
    tags[name] = color
    mongoInstance.updateInDb("pollenisator", "settings", {"key":"tags"}, {"$set": {"value":json.dumps(tags,  cls=JSONEncoder)}}, many=False, notify=True)

    return True

@permission("pentester", "dbName")
def dumpDb(dbName, collection=""):
    """
    Export a database dump into the exports/ folder as a gzip archive.
    It uses the mongodump utily installed with mongodb-org-tools

    Args:
        dbName: the database name to dump
        collection: (Opt.) the collection to dump.
    """
    if dbName != "pollenisator" and dbName not in mongoInstance.listCalendarNames():
        return "Database not found", 404

    if collection != "" and collection not in mongoInstance.db.collection_names():
        return "Collection not found in database provided", 404
    path = mongoInstance.dumpDb(dbName, collection)
    if not os.path.isfile(path):
        return "Failed to export database", 503
    try:
        return send_file(path, mimetype="application/gzip", attachment_filename=os.path.basename(path))
    except TypeError as e: # python3.10.6 breaks https://stackoverflow.com/questions/73276384/getting-an-error-attachment-filename-does-not-exist-in-my-docker-environment
        return send_file(path, mimetype="application/gzip", download_name=os.path.basename(path))
@permission("user")
def importDb(upfile, **kwargs):
    username = kwargs["token_info"]["sub"]
    dirpath = tempfile.mkdtemp()
    tmpfile = os.path.join(dirpath, os.path.basename(upfile.filename))
    with open(tmpfile, "wb") as f:
        f.write(upfile.stream.read())
    success = mongoInstance.importDatabase(username, tmpfile)
    shutil.rmtree(dirpath)
    return success


def doImportCommands(data, user):
    try:
        commands_and_groups = json.loads(data, cls=JSONDecoder)
    except:
        return "Invalid file format, json expected", 400
    if not isinstance(commands_and_groups, dict):
        return "Invalid file format, object expected", 400
    if "commands" not in commands_and_groups.keys():
        return "Invalid file format, object expected property: commands", 400
    if "command_groups" not in commands_and_groups.keys():
        return "Invalid file format, object expected property: command_groups", 400
    if not isinstance(commands_and_groups["commands"], list) or not isinstance(commands_and_groups["command_groups"], list) :
        return "Invalid file format, commands and command_groups properties must be lists", 400
    matchings = {}
    failed = []
    for command in commands_and_groups["commands"]:
        save_id = str(command["_id"])
        del command["_id"]
        command["owners"] = command.get("owners", []) + [user]
        obj_ins = command_insert("pollenisator", command, user)
        if obj_ins["res"]:
            matchings[save_id] = str(obj_ins["iid"])
        else:
            failed.append(command)
    for group in commands_and_groups["command_groups"]:
        del group["_id"]
        old_ids = group["commands"]
        new_ids = [matchings.get(str(old_id)) for old_id in old_ids if matchings.get(str(old_id)) is not None]
        group["commands"] = new_ids
        obj_ins = command_group_insert("pollenisator", group)
        if not obj_ins["res"]:
            failed.append(group)
    return failed

    
@permission("user")
def importCommands(upfile, **kwargs):
    user = kwargs["token_info"]["sub"]
    data = upfile.stream.read()
    return doImportCommands(data, user)
    
def doExportCommands():
    mongoInstance = MongoCalendar.getInstance()
    res = {"commands":[], "command_groups":[]}
    commands = mongoInstance.findInDb("pollenisator", "commands", {}, True)
    for command in commands:
        c = command
        del c["owners"]
        if "users" in c:
            del c["users"]
        res["commands"].append(c)
    g_commands = mongoInstance.findInDb("pollenisator", "group_commands", {}, True)
    for g_command in g_commands:
        g = g_command
        res["command_groups"].append(g)
    return res

@permission("user")
def exportCommands(**kwargs):
    return doExportCommands()
    

@permission("pentester", "body.fromDb")
def copyDb(body):
    toCopyName = body["toDb"]
    fromCopyName = body["fromDb"]
    return mongoInstance.copyDb(fromCopyName, toCopyName)
