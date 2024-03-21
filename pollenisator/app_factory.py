"""
This module contains the main application factory for the Pollenisator server.
"""
import os
import sys
from typing import Dict, Any
import uuid
from getpass import getpass
from pathlib import Path
import json
import ruamel.yaml
import pymongo
import connexion
from flask_cors import CORS
from bson import ObjectId
from flask import Flask, request
import bcrypt
from flask_socketio import SocketIO, join_room, leave_room
from pollenisator.server.modules.worker.worker import removeWorkers, unregister
from pollenisator.core.components.logger_config import logger
from pollenisator.core.components.utils import JSONEncoder, loadServerConfig
from pollenisator.core.components.socketmanager import SocketManager
import pollenisator.core.components.mongo as mongo


server_folder = os.path.join(os.path.dirname(
os.path.realpath(__file__)), "./server/api_specs/")

loaded = False

class BaseConfig(object):
    """
    Redis basic configuration class for the cache.

    Attributes:
        CACHE_TYPE (str): The type of cache to use.
        CACHE_REDIS_HOST (str): The host of the Redis server.
        CACHE_REDIS_PORT (int): The port of the Redis server.
        CACHE_REDIS_DB (int): The database to use in the Redis server.
        CACHE_REDIS_URL (str): The URL of the Redis server.
        CACHE_DEFAULT_TIMEOUT (int): The default timeout for the cache.
    """
    CACHE_TYPE="redis"
    CACHE_REDIS_HOST="localhost"
    CACHE_REDIS_PORT=6379
    CACHE_REDIS_DB=0
    CACHE_REDIS_URL="redis://localhost:6379/0"
    CACHE_DEFAULT_TIMEOUT=500

def create_app(debug: bool, async_mode: str) -> Flask:
    """
    Loads all API yaml modules and initializes the App with SocketIO, Connexion, and Flask.

    Args:
        debug (bool): Whether to run the application in debug mode.
        async_mode (str): The asynchronous mode to use for the application. This should be one of the modes supported by Flask-SocketIO.

    Returns:
        Flask: The initialized Flask application.
    """
    # Read the openapi.yaml file to configure the endpoints
    app = connexion.App(__name__, specification_dir=server_folder, debug=debug)
    flask_app: Flask = app.app
    flask_app.config.from_object(BaseConfig())
    logger.info("LOADING MAIN API")
    if not loaded:
        load_modules(app, os.path.join(server_folder,"openapi.yaml"))

    flask_app = app.app
    # Now that the cache is initialized, set up the cached version of `findInDb`
    sm = SocketManager.getInstance()
    sm.socketio.init_app(flask_app, log_output=False, logger=False,
                    engineio_logger=False, async_mode=async_mode)
    @sm.socketio.event
    def register(data):
        """Registers a worker and associates it with a socket.

        Args:
            data: A dictionary containing the worker's name and list of supported binaries.
        """
        dbclient = mongo.DBClient.getInstance()
        workerName = data.get("name")
        supported_plugins = data.get("supported_plugins", [])
        
        socket = dbclient.findInDb("pollenisator","sockets", {"user":workerName}, False)
        if socket is None:
            dbclient.insertInDb("pollenisator", "sockets", {"sid":request.sid, "user":workerName, "pentest":""}, notify=False)
        else:
            dbclient.updateInDb("pollenisator", "sockets", {"user":workerName}, {"$set":{"sid":request.sid, "pentest":""}}, notify=False)
        dbclient.registerWorker(workerName, supported_plugins)

    @sm.socketio.event
    def registerForNotifications(data):
        """Register the socket for notifications for a specific pentest.

            Args:
                data (dict): A dictionary containing the following keys:
                    - "token" (str): The auth token.
                    - "pentest" (str): The ID of the pentest for which the socket wants to receive notifications.

            Returns:
                None
        """
        from pollenisator.server.token import verifyToken, decode_token

        logger.info("Registering socket for notifications %s", str(data))
        sid = request.sid
        token = str(data.get("token", ""))
        pentest = str(data.get("pentest", ""))
        res = verifyToken(token)
        if res:
            token_info = decode_token(token)
            if pentest in token_info["scope"]:
                dbclient = mongo.DBClient.getInstance()
                socket = dbclient.findInDb("pollenisator", "sockets", {"sid":sid}, False)
                if socket is None:
                    dbclient.insertInDb("pollenisator", "sockets", {"sid":sid, "pentest":pentest}, False)
                else:
                    leave_room(pentest)
                    dbclient.updateInDb("pollenisator", "sockets", {"sid":sid}, {"$set":{"pentest":pentest}}, notify=False)
                join_room(pentest)

    @sm.socketio.event
    def keepalive(data):
        """Keep the worker alive and update the running tasks.

        Args:
            data (dict): A dictionary containing the following keys:
                - "running_tasks" (list): A list of strings representing the IDs of the tools that are currently running.
                - "name" (str): The name of the worker.

        Returns:
            None
        """
        running_tasks = data.get("running_tasks", [])
        workerName = data.get("name")
        dbclient = mongo.DBClient.getInstance()        
        worker = dbclient.findInDb("pollenisator","workers", {"name":workerName}, False)
        if worker is None:
            sm.socketio.emit("deleteWorker", to=request.sid)
            return
        pentest = worker.get("pentest", "")
        if pentest == "":
            return
        for tool_iid in running_tasks:
            tool_d = dbclient.findInDb(pentest, "tools", {"_id":ObjectId(tool_iid)}, False)
            if tool_d is None:
                sm.socketio.emit("stopCommand", {"tool_iid":str(tool_iid), "pentest":pentest}, room=request.sid)
            else:
                if "running" not in tool_d["status"] and "done" not in tool_d["status"]:
                    sm.socketio.emit("stopCommand", {"tool_iid":str(tool_iid), "pentest":pentest}, room=request.sid)

    @sm.socketio.event
    def disconnect():
        """
        Disconnect the socket and unregister it.

        Returns:
            None
        """
        sid = request.sid
        todel = None
        dbclient = mongo.DBClient.getInstance()
        todel = dbclient.findInDb("pollenisator", "sockets", {"sid":sid}, False)
        if todel:
            unregister(todel.get("worker"))
            dbclient.deleteFromDb("pollenisator", "sockets", {"sid":sid}, False)

    @sm.socketio.event
    def test(data):
        logger.info("TEST received : %s", str(data))
        logger.debug(data)
        sm.socketio.emit("test", {"test":"HELLO"}, to=data.get("pentest"))
        
    @sm.socketio.on('get-document')
    def get_document(data):
        sid = request.sid
        dbclient = mongo.DBClient.getInstance()
        socket = dbclient.findInDb("pollenisator", "sockets", {"sid":sid}, False)
        if socket is None:
            return {"error":"Forbidden"}
        if not(socket["pentest"] == data.get("pentest") and data.get("pentest") is not None):
            return {"error":"Forbidden"}
        pentest = data.get("pentest","")
        doc = dbclient.findInDb(pentest, "documents", {"pentest":pentest}, False)
        if doc is None:
            ins_result = dbclient.insertInDb(pentest, "documents", {"data":{}, "pentest":pentest})
            if ins_result is None:
                return {"error": "Document could not be created"}
            res = ins_result.inserted_id
            doc = {}
        sm.socketio.emit("load-document", doc.get("data", {}), room=request.sid)
    
    @sm.socketio.on("send-delta")
    def send_delta(delta):
        sid = request.sid
        dbclient = mongo.DBClient.getInstance()
        socket = dbclient.findInDb("pollenisator", "sockets", {"sid":sid}, False)
        if socket is None:
            return {"error":"Forbidden"}
        if socket["pentest"] == "":
            return {"error":"Forbidden"}
        pentest = socket["pentest"]
        sm.socketio.emit("received-delta", delta, room=pentest, include_self=False)
    @sm.socketio.on("save-document")
    def save_document(data):
        dbclient = mongo.DBClient.getInstance()
        sid = request.sid
        socket = dbclient.findInDb("pollenisator", "sockets", {"sid":sid}, False)
        if socket is None:
            return {"error":"Forbidden"}
        if socket["pentest"] == "":
            return {"error":"Forbidden"}
        pentest = socket["pentest"]
        dbclient.updateInDb(pentest, "documents", {"pentest":pentest}, {"$set":{"data":data}})

    flask_app.json_encoder = JSONEncoder
    logger.info('Running ...')
    CORS(flask_app)
    return flask_app


def load_modules(app: Any, main_file: str)->None:
    """Loads all YAML files in the modules folder and merges them into one file.

    Args:
        app (Any): The Connexion app object.
        main_file (str): The path to the main YAML file.
    """

    modules_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "./server/modules/")
    # Load modules
    yaml = ruamel.yaml.YAML()
    with open(main_file , encoding="utf-8") as fp:
        specs = yaml.load(fp)
        for path in Path(modules_path).rglob('*.yaml'):
            print("LOADING MODULE "+str(path))
            with open(path , encoding="utf-8") as fp2:
                module_specs = yaml.load(fp2)
                if module_specs is None:
                    continue
                if "components" in module_specs and "schemas" in module_specs["components"]:
                    for i in module_specs["components"]["schemas"]:
                        specs["components"]["schemas"].update({i:module_specs["components"]["schemas"][i]})
                for i in module_specs["paths"]:
                    specs["paths"].update({i:module_specs["paths"][i]})
      
        with open('/tmp/bundled.yaml', 'w', encoding="utf-8") as fw:
            yaml.dump(specs, fw)
            app.add_api('/tmp/bundled.yaml')
            global loaded
            loaded = True


def create_admin(username: str = "", password: str = "") -> None:
    """Prompts the user to enter a username and password and creates a new admin account with those credentials.

    Args:
        username: The desired username.
        password: The desired password.
    """
    print("The user database is empty, create an admin now")
    if username.strip() == "":
        username = input("username: ")
        while username.strip() == "":
            print("username cannot be empty")
            username = input("username: ")
    if password.strip() == "":
        password = getpass("password: ")
        while password.strip() == "":
            print("Password cannot be empty")
            password = getpass("password: ")
    salt = bcrypt.gensalt()
    dbclient = mongo.DBClient.getInstance()
    dbclient.insertInDb("pollenisator", "users", {"username": username, "hash": bcrypt.hashpw(
        password.encode(), salt), "scope": ["admin", "user"]})
    print("Administrator created")


def notify_clients(notif: Dict[str, Any]) -> None:
    """
    Notify clients via websockets.

    Args:
        notif (Dict[str, Any]): A dictionary containing the notification details. It should contain a "db" key with the name of the database the notification is associated with.

    If the "db" key is "pollenisator", the notification is sent to all clients. Otherwise, it is sent only to the clients associated with the specified database.
    """
    sm = SocketManager.getInstance()
    #sockets = dbclient.findInDb("pollenisator","sockets",{}, True)
    if notif["db"] == "pollenisator":
        sm.socketio.emit("notif", json.dumps(notif, cls=JSONEncoder))
    else:
        sm.socketio.emit("notif", json.dumps(notif, cls=JSONEncoder), to=notif["db"])

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
                outpath = dbclient.dumpDb(pentest["nom"])
                dbclient.importDatabase(dbclient.getPentestOwner(pentest["nom"]), outpath, nsFrom=pentest["nom"], nsTo=pentest["uuid"])
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
    dbclient.updateInDb("pollenisator","infos",{"key":"version"},{"$set":{"key":"version","value":"2.8"}})

def init_db() -> None:
    """
    Initialize empty databases or remaining tmp data from the last run.

    This function connects to the database, deletes any remaining socket data, checks for existing users, and creates an admin user if none exist. It also handles command-line arguments for non-interactive mode and help. Finally, it performs database migration and removes any remaining workers.
    """
    dbclient = mongo.DBClient.getInstance()
    dbclient.deleteFromDb("pollenisator", "sockets", {}, many=True, notify=False)
    res = dbclient.findInDb("pollenisator", "settings", {}, True)
    if res is None:
        settings = []
    else:
        settings = [s for s in res]
    if len(settings) < 2 or settings[0].get("key") != "pentest_types" or settings[1].get("key") != "tags":
        dbclient.insertInDb("pollenisator", "settings", {"key":"pentest_types", "value":'{"Web": ["Base", "Application", "Data", "Policy"], "LAN": ["Base", "Application", "Infrastructure", "Active Directory", "Data", "Policy"]}'})
        dbclient.insertInDb("pollenisator", "settings", {"key":"tags", "value":'{"todo": {"color": "orange", "level": "todo"}, "pwned": {"color": "red", "level": "high"}, "Interesting": {"color": "dark green", "level": "medium"}, "Uninteresting": {"color": "sky blue", "level": "low"}, "neutral": {"color": "transparent", "level": ""}}'})
    any_user = dbclient.findInDb("pollenisator", "users", {}, False)
    noninteractive = False
    if any_user is None:
        for arg in sys.argv:
            if arg == "-h" or "--help":
                print("""Usage : pollenisator [-h|--help] [--non-interactive]
                Python3.7+ is required
                Options:
                    -h | --help : print this help
                    --non-interactive : does not prompt for anything (WARNING : a default user will be created with admin:admin credentials if no user previously exist)
                """)
            if arg == "--non-interactive":
                noninteractive = True
        if noninteractive:
            create_admin("admin", "admin")
        else:
            create_admin()
        #createWorker()
    migrate()
    removeWorkers()
    #TODO FIX TAKES TOO MUCH TIME OR ADD OPTION TO DO SO dbclient.resetRunningTools()

def init_config() -> int:
    """
    Initialize the server configuration.

    This function loads the server configuration, sets the port number, and determines whether to use SSL based on the configuration and environment variables.

    Returns:
        int: The port number to use for the server.
    """
    conf = loadServerConfig()
    port = int(os.environ.get("POLLENISATOR_PORT", conf.get("api_port", 5000)))
    https = os.environ.get("POLLENISATOR_SSL",conf.get("https", "false").lower() == "true")
    if https:
        ssl_context = "adhoc"
    else:
        ssl_context = None
    return port

def run(flask_app: Flask, debug: bool) -> SocketIO:
    """
    Run the Flask application with SocketIO.

    Args:
        flask_app (Flask): The Flask application to run.
        debug (bool): Whether to run the application in debug mode.

    Returns:
        SocketIO: The SocketIO instance associated with the Flask application.

    Raises:
        KeyboardInterrupt: If the application is interrupted by the user.
    """
    sm = SocketManager.getInstance()
    port = init_config()
    init_db()
    try:
        sm.socketio.run(flask_app, host=os.environ.get("POLLENISATOR_BIND_IP", '0.0.0.0'), port=port,
                     debug=debug, use_reloader=False, )
    except KeyboardInterrupt:
        pass
    return sm.socketio