import pymongo
import pollenisator.core.components.mongo as mongo
from pollenisator.core.components.logger_config import logger
import uuid
import os
from pollenisator.core.components.utils import getMainDir
from bson import ObjectId
from typing import Dict, List, Union

def migrate():
    dbclient = mongo.DBClient.getInstance()
    version = dbclient.findInDb("pollenisator","infos",{"key":"version"}, False)
    if version is None:
        dbclient.insertInDb("pollenisator","infos",{"key":"version","value":"2.7"})
        return
    else:
        version = version["value"]
    if version == "0":
        version = migrate_0()
    if version == "1":
        version = migrate_1()
    if version == "1.1":
        version = migrate_1_1()
    if version == "1.2":
        version = migrate_2_5()
    if version == "2.5":
        version = migrate_2_6()
    if version == "2.6":
        version = migrate_2_7()
    if version == "2.7":
        version = migrate_2_8()
    if version == "2.8":
        version = migrate_2_9()
    if version == "2.9":
        version = migrate_2_10()
    if version == "2.10":
        version = migrate_2_11()
    if version == "2.11":
        version = migrate_2_12()
    if version == "2.12":
        version = migrate_2_13()
    if version == "2.13":
        version = migrate_2_14()
    if version == "2.14":
        version = migrate_2_15()
    if version == "2.15":
        version = migrate_2_16()
    logger.info("DB version is %s", version)

def migrate_0():
    dbclient = mongo.DBClient.getInstance()
    dbclient.client["pollenisator"]["calendars"].rename("pentests")
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"1"}})
    return "1"

def migrate_1():
    dbclient = mongo.DBClient.getInstance()
    pentests = dbclient.findInDb("pollenisator","pentests",{}, True)
    for pentest in pentests:
        dbclient.updateInDb("pollenisator", "pentests", {"_id":ObjectId(pentest["_id"])}, {"$set":{"uuid":str(uuid.uuid4())}})
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"1.1"}})
    return "1.1"

def migrate_1_1():
    dbclient = mongo.DBClient.getInstance()
    pentests = dbclient.findInDb("pollenisator","pentests",{}, True)
    dbs = dbclient.client.list_database_names()
    for pentest in pentests:
        if pentest["uuid"] not in dbs:
            print("missing pentest uuid, exporting it:")
            try:
                outpath,status_code = dbclient.dumpDb(pentest["nom"])
                if status_code == 200:
                    dbclient.importDatabase(dbclient.getPentestOwner(pentest["nom"]), outpath, nsFrom=pentest["nom"], nsTo=pentest["uuid"])
                else:
                    print("Error exporting pentest %s" % pentest["nom"])
            except ValueError as e:
                pass
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"1.2"}})
    return "1.2"

def migrate_2_5():
    dbclient = mongo.DBClient.getInstance()
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"2.5"}})
    return "2.5"

def migrate_2_6():
    dbclient = mongo.DBClient.getInstance()
    dbclient.deleteFromDb("pollenisator","settings",{"key":"tags"})
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"2.6"}})
    pentests = dbclient.findInDb("pollenisator","pentests",{}, True)
    for pentest in pentests:
        dbclient.updateInDb(pentest["uuid"], "settings", {"key":"tags"}, {"$set":{"key":"tags", "value":{}}})
    return "2.6"

def migrate_2_7():
    dbclient = mongo.DBClient.getInstance()
    pentests = dbclient.findInDb("pollenisator","pentests",{}, True)
    for pentest in pentests:
        users = dbclient.findInDb(pentest["uuid"], "ActiveDirectory", {"type":"user"}, True)
        for user in users:
            dbclient.insertInDb(pentest["uuid"], "users", user)
        computers = dbclient.findInDb(pentest["uuid"], "ActiveDirectory", {"type":"computer"}, True)
        for computer in computers:
            dbclient.insertInDb(pentest["uuid"], "computers", computer)
        shares = dbclient.findInDb(pentest["uuid"], "ActiveDirectory", {"type":"share"}, True)
        for share in shares:
            dbclient.insertInDb(pentest["uuid"], "shares", share)
        db = dbclient.client[pentest["uuid"]]
        try:
            db["cheatsheet"].rename("checkinstances")
        except pymongo.errors.OperationFailure:
            pass
    db = dbclient.client["pollenisator"]
    db["cheatsheet"].rename("checkitems")
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"2.7"}})
    return "2.7"


def migrate_2_8():
    dbclient = mongo.DBClient.getInstance()
    # update iid strings to ObjectIds
    logger.info("Converting Checkitems in pollenisator")
    checks = dbclient.findInDb("pollenisator","checkitems",{}, True)
    if checks:
        for check in checks:
            new_commands = []
            new_defects = []
            new_defect_tags = []
            for command in check.get("commands", []):
                new_commands.append(ObjectId(command))
            for defect in check.get("defects", []):
                new_defects.append(ObjectId(defect))
            for defect_tag in check.get("defect_tags", []):
                if len(defect_tag) > 1:
                    defect_tag[1] = ObjectId(defect_tag[1])
                new_defect_tags.append(defect_tag)
            dbclient.updateInDb("pollenisator","checkitems",{"_id":ObjectId(check["_id"])},{"$set":{"commands":new_commands, "defects":new_defects, "defect_tags":new_defect_tags}})
    # iterate pentests
    logger.info("Start iterating pentests.")
    pentests = list(dbclient.findInDb("pollenisator","pentests",{}, True))
    for pentest in pentests:
        pentest_uuid = pentest["uuid"]
        logger.info("Migrating pentest %s (%s) %d/%d", pentest["nom"], pentest_uuid, pentests.index(pentest), len(pentests))
        # update iid strings to ObjectIds
        check_instances = dbclient.findInDb(pentest_uuid,"checkinstances", {}, True)
        updates = []
        if check_instances:
            for check_instance in check_instances:
                try:
                    check_instance["check_iid"] = ObjectId(check_instance["check_iid"])
                except Exception:
                    pass
                try:
                    check_instance["target_iid"] = ObjectId(check_instance["target_iid"])
                except Exception:
                    pass
                updates.append(pymongo.UpdateOne({"_id":ObjectId(check_instance["_id"])},{"$set":{"check_iid":check_instance["check_iid"], "target_iid":check_instance["target_iid"]}}))
            dbclient.bulk_write(pentest_uuid, "checkinstances", updates)
        updates = []
        commands = dbclient.findInDb(pentest_uuid,"commands", {}, True)
        if commands:
            for command in commands:
                try:
                    command["original_iid"] = ObjectId(command["original_iid"])
                except Exception:
                    pass
                updates.append(pymongo.UpdateOne({"_id":ObjectId(command["_id"])},{"$set":{"original_iid":command.get("original_iid")}}))
            dbclient.bulk_write(pentest_uuid, "commands", updates)
        defects = dbclient.findInDb(pentest_uuid,"defects", {}, True)
        updates = []
        if defects:
            for defect in defects:
                try:
                    defect["target_id"] = ObjectId(defect["target_id"])
                except Exception:
                    pass
                updates.append(pymongo.UpdateOne({"_id":ObjectId(defect["_id"])}, {"$set":{"target_id":defect.get("target_id")}}))
                dbclient.bulk_write(pentest_uuid, "defects", updates)
        ips = dbclient.findInDb(pentest_uuid,"ips", {}, True)
        updates = []
        if ips:
            for ip in ips:
                new_in_scopes = []
                for in_scope in ip.get("in_scopes", []):
                    new_in_scopes.append(ObjectId(in_scope))
                updates.append(pymongo.UpdateOne({"_id":ObjectId(ip["_id"])},{"$set":{"in_scopes":new_in_scopes}}))
            dbclient.bulk_write(pentest_uuid, "ips", updates)
        updates = []
        tools = dbclient.findInDb(pentest_uuid, "tools", {}, True)
        if tools:
            for tool in tools:
                try:
                    tool["check_iid"] = ObjectId(tool["check_iid"])
                except Exception:
                    pass
                try:
                    tool["command_iid"] = ObjectId(tool["command_iid"])
                except Exception:
                    pass
                updates.append(pymongo.UpdateOne({"_id":ObjectId(tool["_id"])},{"$set":{"check_iid":tool.get("check_iid"), "command_iid":tool.get("command_iid")}}))
            dbclient.bulk_write(pentest_uuid, "tools", updates)
    logger.info("End of Migrating pentest")
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"2.8"}})
    return "2.8"

def migrate_2_9():
    dbclient = mongo.DBClient.getInstance()
    defects = dbclient.findInDb("pollenisator","defects",{}, True)
    updates = []
    for defect in defects:
        types = defect.get("type", None)
        newType = set()
        if isinstance(types, str):
            newType = newType.union(set([x.strip() for x in types.split(",")]))
        elif isinstance(types, list):
            for item in types:
                if isinstance(item, str):
                    newType = newType.union(set([x.strip() for x in item.split(",")]))
        newTypeList = list(newType)
        perimeter = defect.get("perimeter", None)
        if perimeter is None:
            perimeter = "all"
        updates.append(pymongo.UpdateOne({"_id":ObjectId(defect["_id"])},{"$set":{"type":newTypeList, "perimeter":perimeter}}))
    dbclient.bulk_write("pollenisator", "defects", updates)
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"2.9"}})
    return "2.9"


def migrate_2_10():
    dbclient = mongo.DBClient.getInstance()
    defects = dbclient.findInDb("pollenisator","defects",{}, True)
    updates = []
    for defect in defects:
        perimeters = defect.get("perimeter", None)
        newPerimeters = set()
        if isinstance(perimeters, str):
            newPerimeters = newPerimeters.union(set([x.strip() for x in perimeters.split(",")]))
        elif isinstance(perimeters, list):
            for item in perimeters:
                if isinstance(item, str):
                    newPerimeters = newPerimeters.union(set([x.strip() for x in item.split(",")]))
        newPerimeterList = list(newPerimeters)
        perimeter = defect.get("perimeter", None)
        if perimeter is None:
            perimeter = ["all"]
        updates.append(pymongo.UpdateOne({"_id":ObjectId(defect["_id"])},{"$set":{"perimeter":newPerimeterList}}))
    dbclient.bulk_write("pollenisator", "defects", updates)
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"2.10"}})
    return "2.10"

def migrate_2_11():
    dbclient = mongo.DBClient.getInstance()
    logger.info("Start iterating pentests.")
    pentests = list(dbclient.findInDb("pollenisator","pentests",{}, True))
    for pentest in pentests:
        pentest_uuid = pentest["uuid"]
        logger.info("Migrating pentest %s (%s) %d/%d", pentest["nom"], pentest_uuid, pentests.index(pentest), len(pentests))
        # update iid strings to ObjectIds
        dbclient.updateInDb(pentest_uuid, "defects", {}, {"$set":{"redacted_state":"New"}}, many=True)
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"2.11"}})
    return "2.11"

def migrate_2_12():
    dbclient = mongo.DBClient.getInstance()
    logger.info("Start iterating pentests.")
    pentests = list(dbclient.findInDb("pollenisator","pentests",{}, True))
    for pentest in pentests:
        pentest_uuid = pentest["uuid"]
        logger.info("Migrating pentest %s (%s) %d/%d", pentest["nom"], pentest_uuid, pentests.index(pentest), len(pentests))
        # update iid strings to ObjectIds
        dbclient.updateInDb(pentest_uuid, "defects", {}, {"$set":{"impacts":""}}, many=True)
    dbclient.updateInDb("pollenisator","defects", {}, {"$set":{"impacts":""}}, many=True)
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"2.12"}})
    return "2.12"

def migrate_2_13():
    dbclient = mongo.DBClient.getInstance()
    # list pentests files and create their database version
    logger.info("Start iterating pentests.")
    file_local_path = os.path.normpath(os.path.join(getMainDir(), "files"))
    pentests = os.listdir(file_local_path)
    for pentest in pentests:
        if not os.path.exists(os.path.join(file_local_path, pentest)) or not os.path.isdir(os.path.join(file_local_path, pentest)):
            continue
        print("Migrating pentest %s" % pentest)
        #files
        if not os.path.exists(os.path.join(file_local_path, pentest, "file")):
            continue
        attached_to_ids = os.listdir(os.path.join(file_local_path, pentest, "file"))
        if len(attached_to_ids) > 0:
            for attached_to_id in attached_to_ids:
                attached_file = os.path.join(file_local_path, pentest, "file", attached_to_id)
                if not os.path.exists(attached_file) or not os.path.isdir(attached_file):
                    continue

                files = os.listdir(attached_file)
                if len(files) > 0:
                    for attached in files:
                        attached_path = os.path.join(attached_file, attached)
                        if not os.path.exists(attached_path) or not os.path.isfile(attached_path):
                            continue
                        attached_id = str(uuid.uuid4())
                        dbclient.insertInDb(pentest, "attachments", {"attachment_id":attached_id, "name":attached, "attached_to":attached_to_id, "type":"file"})
                        logger.info("Inserted attachment %s for pentest %s", attached_id, pentest)
        #proofs
    for pentest in pentests:
        if not os.path.exists(os.path.join(file_local_path, pentest, "proof")):
            continue
        attached_to_ids = os.listdir(os.path.join(file_local_path, pentest, "proof"))
        if len(attached_to_ids) > 0:
            for attached_to_id in attached_to_ids:
                attached_file = os.path.join(file_local_path, pentest, "proof", attached_to_id)
                if not os.path.exists(attached_file) or not os.path.isdir(attached_file):
                    continue

                files = os.listdir(attached_file)
                if len(files) > 0:
                    for attached in files:
                        attached_path = os.path.join(attached_file, attached)
                        if not os.path.isfile(attached_path):
                            continue
                        attached_id = str(uuid.uuid4())
                        dbclient.insertInDb(pentest, "attachments", {"attachment_id":attached_id, "name":attached, "attached_to":attached_to_id, "type":"proof"})
                        logger.info("Inserted proof %s for pentest %s", attached_id, pentest)
    for pentest in pentests: 
        # results
        if not os.path.exists(os.path.join(file_local_path, pentest, "result")):
            continue
        attached_to_ids = os.listdir(os.path.join(file_local_path, pentest, "result"))
        if len(attached_to_ids) > 0:
            for attached_to_id in attached_to_ids:
                attached_file = os.path.join(file_local_path, pentest, "result", attached_to_id)
                if not os.path.exists(attached_file) or not os.path.isdir(attached_file):
                    continue

                files = os.listdir(attached_file)
                if len(files) > 0:
                    for attached in files:
                        attached_path = os.path.join(attached_file, attached)
                        if not os.path.exists(attached_path) or not os.path.isfile(attached_path):
                            continue
                        attached_id = str(uuid.uuid4())
                        dbclient.insertInDb(pentest, "attachments", {"attachment_id":attached_id, "name":attached,  "attached_to":attached_to_id, "type":"result"})
                        logger.info("Inserted result %s for pentest %s", attached_id, pentest)
   
    dbclient.updateInDb(
        "pollenisator",
        "infos",
        {"key": "version"},
        {"$set": {"key": "version", "value": "2.13"}}
    )
    return "2.13"

def migrate_2_14():
    dbclient = mongo.DBClient.getInstance()
    pentests = dbclient.findInDb("pollenisator","pentests",{}, True)
    for pentest in pentests:
        pentest_uuid = pentest["uuid"]
        logger.info("Migrating pentest %s (%s)", pentest["nom"], pentest_uuid)
        pentesters_setting = dbclient.findInDb(pentest_uuid, "settings", {"key":"pentesters"}, False)
        pentesters = []
        if pentesters_setting is not None:
            pentesters = pentesters_setting.get("value", [])
        if pentest.get("owner", None) is not None:
            if pentest["owner"] not in pentesters:
                pentesters.append(pentest["owner"])
        dbclient.updateInDb("pollenisator", "pentests", {"uuid":pentest_uuid}, {"$set":{"pentesters":pentesters}})
        dbclient.deleteFromDb(pentest_uuid, "settings", {"key":"pentesters"}, True)
    dbclient.updateInDb(
        "pollenisator",
        "infos",
        {"key": "version"},
        {"$set": {"key": "version", "value": "2.14"}}
    )
    return "2.14"

def migrate_2_15():
    """add defect_id to defects"""
    dbclient = mongo.DBClient.getInstance()
    defects = dbclient.findInDb("pollenisator","defects",{}, True)
    updates = []
    updates_suggestions = []
    
    for defect in defects:
        defect_id = None
        common_translation_id = None
        if "defect_id" not in defect:
            defect_id = str(uuid.uuid4())
            updates.append(pymongo.UpdateOne({"_id":ObjectId(defect["_id"])},{"$set":{"defect_id":defect_id}}))
        else:
            defect_id = defect["defect_id"]
        if "common_translation_id" not in defect:
            common_translation_id = str(uuid.uuid4())
            updates.append(pymongo.UpdateOne({"_id":ObjectId(defect["_id"])},{"$set":{"common_translation_id":common_translation_id}}))
        else:
            common_translation_id = defect["common_translation_id"]
        updates_suggestions.append(pymongo.UpdateOne({"_id":ObjectId(defect["_id"])},{"$set":{"defect_id":defect_id}}))
        updates_suggestions.append(pymongo.UpdateOne({"_id":ObjectId(defect["_id"])},{"$set":{"common_translation_id":common_translation_id}}))
    if len(updates) > 0:
        dbclient.bulk_write("pollenisator", "defects", updates)
    if len(updates_suggestions) > 0:
        dbclient.bulk_write("pollenisator", "defectssuggestions", updates_suggestions)
    pentests = dbclient.findInDb("pollenisator","pentests",{}, True)
    for pentest in pentests:
        pentest_uuid = pentest["uuid"]
        logger.info("Migrating pentest %s (%s)", pentest["nom"], pentest_uuid)
        defects = dbclient.findInDb(pentest_uuid,"defects",{}, True)
        updates = []
        for defect in defects:
            if "defect_id" not in defect:
                defect_id = str(uuid.uuid4())
                updates.append(pymongo.UpdateOne({"_id":ObjectId(defect["_id"])},{"$set":{"defect_id":defect_id}}))
            if "common_translation_id" not in defect:
                common_translation_id = str(uuid.uuid4())
                updates.append(pymongo.UpdateOne({"_id":ObjectId(defect["_id"])},{"$set":{"common_translation_id":common_translation_id}}))
        if len(updates) > 0:
            dbclient.bulk_write(pentest_uuid, "defects", updates)

    dbclient.updateInDb(
        "pollenisator",
        "infos",
        {"key": "version"},
        {"$set": {"key": "version", "value": "2.15"}}
    )
    return "2.15"

def migrate_2_16():
    dbclient = mongo.DBClient.getInstance()
    updates_suggestions = []
    defects_suggestions = dbclient.findInDb("pollenisator","defectssuggestions",{}, True)
    for sugg in defects_suggestions:
        defect_id = None
        common_translation_id = None
        if "defect_id" not in sugg:
            defect_id = str(uuid.uuid4())
            updates_suggestions.append(pymongo.UpdateOne({"_id":ObjectId(sugg["_id"])},{"$set":{"defect_id":defect_id}}))
        else:
            defect_id = sugg["defect_id"]
        if "common_translation_id" not in sugg:
            common_translation_id = str(uuid.uuid4())
            updates_suggestions.append(pymongo.UpdateOne({"_id":ObjectId(sugg["_id"])},{"$set":{"common_translation_id":common_translation_id}}))
        else:
            common_translation_id = sugg["common_translation_id"]
    if len(updates_suggestions) > 0:
        dbclient.bulk_write("pollenisator", "defectssuggestions", updates_suggestions)
    dbclient.updateInDb(
        "pollenisator",
        "infos",
        {"key": "version"},
        {"$set": {"key": "version", "value": "2.16"}}
    )
    return "2.16"
