import json
import os
from bson import ObjectId
from datetime import datetime
from flask import send_file
import tempfile
import shutil
from core.Components.mongo import MongoCalendar
from core.Components.Utils import JSONDecoder, getMainDir
from core.Controllers.CommandController import CommandController
from core.Controllers.WaveController import WaveController
from core.Controllers.IntervalController import IntervalController
from server.ServerModels.Command import ServerCommand
from server.ServerModels.Command import insert as insert_command
from server.ServerModels.Wave import ServerWave, insert as insert_wave
from server.ServerModels.Interval import ServerInterval, insert as insert_interval
from server.ServerModels.Scope import insert as insert_scope
from server.FileManager import deletePentestFiles
mongoInstance = MongoCalendar.getInstance()

validCollections = ["group_commands", "commands", "settings"]


def status():
    mongoInstance.connect()
    return mongoInstance.client != None

def update(pentest, collection, data):
    pipeline = data["pipeline"] if data["pipeline"] is not None else "{}"
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    updatePipeline = data["updatePipeline"]
    if isinstance(updatePipeline, str):
        updatePipeline = json.loads(updatePipeline, cls=JSONDecoder)
    if not isinstance(updatePipeline, dict):
        return "Pipeline argument was not valid", 400
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    return mongoInstance.updateInDb(pentest, collection, pipeline, updatePipeline, data["many"], data["notify"])

def insert(pentest, collection, data):
    pipeline = data["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.insertInDb(pentest, collection, pipeline, data["parent"], data["notify"])
    return str(res.inserted_id)

def find(pentest, collection, data):
    pipeline = data["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.findInDb(pentest, collection, pipeline, data["many"])
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

def count(pentest, collection, data):
    pipeline = data["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.findInDb(pentest, collection, pipeline, True).count()
    return res

def fetchNotifications(pentest, fromTime):
    res = mongoInstance.fetchNotifications(pentest, fromTime)
    if res is None:
        return []
    return [n for n in res]

def aggregate(pentest, collection, pipelines):
    ret = []
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.aggregateFromDb(pentest, collection, pipelines)
    for r in res:
        ret.append(r)
    return ret

def delete(pentest, collection, data):
    pipeline = data["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not a valid dictionnary", 400
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.deleteFromDb(pentest, collection, pipeline, data["many"], data["notify"])
    if res is None:
        return
    else:
        return res.deleted_count

def listPentests():
    ret = mongoInstance.listCalendars()
    if ret:
        return ret
    else:
        return "Server connection issue", 503

def deletePentest(pentest):
    ret = mongoInstance.doDeleteCalendar(pentest)
    if ret:
        deletePentestFiles(pentest)
        return "Successful deletion"
    else:
        return  "Unknown pentest", 404

def registerCalendar(pentest, data):
    ret, msg = mongoInstance.registerCalendar(pentest, False, False)
    if ret:
        prepareCalendar(pentest, data["pentest_type"], data["start_date"], data["end_date"], data["scope"], data["settings"], data["pentesters"])
        return msg
    else:
        return msg, 403

def prepareCalendar(dbName, pentest_type, start_date, end_date, scope, settings, pentesters):
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
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(dbName)
    commands = ServerCommand.getList({"$or":[{"types":{"$elemMatch":{"$eq":pentest_type}}}, {"types":{"$elemMatch":{"$eq":"Commun"}}}]})
    if not commands:
        commandslist = ServerCommand.getList()
        if not commandslist:
            default = os.path.join(getMainDir(), "exports/pollenisator_commands.gz")
            res = mongoInstance.importCommands(default)
            if res:
                default = os.path.join(getMainDir(), "exports/pollenisator_group_commands.gz")
                res = mongoInstance.importCommands(default)
        commands = ServerCommand.getList({"$or":[{"types":{"$elemMatch":{"$eq":pentest_type}}}, {"types":{"$elemMatch":{"$eq":"Commun"}}}]})
    # Duplicate commands in local database
    allcommands = ServerCommand.fetchObjects({})
    for command in allcommands:
        command.indb = dbName
        insert_command(command.indb, CommandController(command).getData())
    wave_o = ServerWave().initialize(dbName, commands)
    insert_wave(dbName, WaveController(wave_o).getData())
    interval_o = ServerInterval().initialize(dbName, start_date, end_date)
    insert_interval(dbName, IntervalController(interval_o).getData())
    for scope in scope.split("\n"):
        if scope.strip() != "":
            insert_scope(dbName, {"wave":dbName, "scope":scope.strip()})
    mongoInstance.insert("settings", {"key":"pentest_type", "value":pentest_type})
    mongoInstance.insert("settings", {"key":"include_domains_with_ip_in_scope", "value": settings['Add domains whose IP are in scope'] == 1})
    mongoInstance.insert("settings", {"key":"include_domains_with_topdomain_in_scope", "value":settings["Add domains who have a parent domain in scope"] == 1})
    mongoInstance.insert("settings", {"key":"include_all_domains", "value":settings["Add all domains found"] == 1})
    mongoInstance.insert("settings", {"key":"pentesters", "value":list(map(lambda x: x.strip(), pentesters.split("\n")))})

def getSettings():
    res = mongoInstance.findInDb("pollenisator", "settings", {}, True)
    if res is None:
        return []
    return [s for s in res]

def getSetting(pipeline):
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    return mongoInstance.findInDb("pollenisator", "settings", pipeline, False)

def createSetting(data):
    key = data['key']
    value = data["value"]
    res = mongoInstance.insertInDb("pollenisator", "settings", {"key":key, "value":value})
    if res:
        return True
    return False
    
def updateSetting(data):
    key = data['key']
    value = data["value"]
    return mongoInstance.updateInDb("pollenisator", "settings", {
                    "key": key}, {"$set": {"value": value}})

def dumpDb(dbName, collection=""):
    """
    Export a database dump into the exports/ folder as a gzip archive.
    It uses the mongodump utily installed with mongodb-org-tools

    Args:
        dbName: the database name to dump
        collection: (Opt.) the collection to dump.
    """
    if dbName != "pollenisator" and dbName not in mongoInstance.listCalendars():
        return "Database not found", 404
    mongoInstance.connectToDb(dbName)
    if collection != "" and collection not in mongoInstance.db.collection_names():
        return "Collection not found in database provided", 404
    path = mongoInstance.dumpDb(dbName, collection)
    if not os.path.isfile(path):
        return "Failed to export database", 503
    return send_file(path, attachment_filename=os.path.basename(path))

def importDb(upfile):
    dirpath = tempfile.mkdtemp()
    tmpfile = os.path.join(dirpath, os.path.basename(upfile.filename))
    with open(tmpfile, "wb") as f:
        f.write(upfile.stream.read())
    success = mongoInstance.importDatabase(tmpfile)
    shutil.rmtree(dirpath)
    return success

def importCommands(upfile):
    dirpath = tempfile.mkdtemp()
    tmpfile = os.path.join(dirpath, os.path.basename(upfile.filename))
    with open(tmpfile, "wb") as f:
        f.write(upfile.stream.read())
    success = mongoInstance.importCommands(tmpfile)
    shutil.rmtree(dirpath)
    return success

def copyDb(data):
    toCopyName = data["toDb"]
    fromCopyName = data["fromDb"]
    return mongoInstance.copyDb(fromCopyName, toCopyName)