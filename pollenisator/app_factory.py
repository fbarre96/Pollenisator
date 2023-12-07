import os
import connexion
server_folder = os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "./server/api_specs/")


# Create a URL route in our application for "/"
import pollenisator.core.components.mongo as mongo

# ENABLE LOGGING EARLY ON
from pollenisator.core.components.logger_config import logger
from flask_cors import CORS
from getpass import getpass
from bson import ObjectId
from pollenisator.core.components.utils import JSONEncoder, loadServerConfig
from pollenisator.core.components.socketmanager import SocketManager
from flask import request
import sys
import bcrypt
import json
from pollenisator.server.modules.worker.worker import removeWorkers, unregister
from pathlib import Path
import ruamel.yaml
from flask_socketio import join_room, leave_room
import pymongo

loaded = False

class BaseConfig(object):
    CACHE_TYPE="redis"
    CACHE_REDIS_HOST="localhost"
    CACHE_REDIS_PORT=6379
    CACHE_REDIS_DB=0
    CACHE_REDIS_URL="redis://localhost:6379/0"
    CACHE_DEFAULT_TIMEOUT=500

def create_app(debug, async_mode):
    """Loads all API ymal modules and init the App with SocketIO + Connexion + Flask
    """
    # Read the openapi.yaml file to configure the endpoints
    app = connexion.App(__name__, specification_dir=server_folder, debug=debug)
    flask_app = app.app
    flask_app.config.from_object(BaseConfig())
    logger.info("LOADING MAIN API")
    if not loaded:
        load_modules(app, os.path.join(server_folder,"openapi.yaml"))

    flask_app = app.app
    # Now that the cache is initialized, set up the cached version of `findInDb`
    sm = SocketManager.getInstance()
    logger.info('Running ...')
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

        logger.info("Registering socket for notifications "+str(data))
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
        """Disconnect the socket and unregister it.

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
        logger.info("TEST received : "+str(data))
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
    CORS(flask_app)
    return flask_app


    
def load_modules(app, main_file):
    """Loads all YAML files in the modules folder and merges them into one file.

    Args:
        app: The Connexion app object.
        main_file: The path to the main YAML file.
    """

    modules_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "./server/modules/")
    # Load modules
    yaml = ruamel.yaml.YAML()
    with open(main_file) as fp:
        specs = yaml.load(fp)
        for path in Path(modules_path).rglob('*.yaml'):
            print("LOADING MODULE "+str(path))
            with open(path) as fp2:
                module_specs = yaml.load(fp2)
                if module_specs is None:
                    continue
                if "components" in module_specs and "schemas" in module_specs["components"]:
                    for i in module_specs["components"]["schemas"]:
                        specs["components"]["schemas"].update({i:module_specs["components"]["schemas"][i]})
                for i in module_specs["paths"]:
                    specs["paths"].update({i:module_specs["paths"][i]})
      
        with open('/tmp/bundled.yaml', 'w') as fw:
            yaml.dump(specs, fw)
            app.add_api('/tmp/bundled.yaml')
            global loaded
            loaded = True
        


def create_admin(username="", password=""):
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


def notify_clients(notif):
    """Notify clients websockets
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
        dbclient.insertInDb("pollenisator","infos",{"key":"version","value":"0"})
        version = "0"
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
            outpath = dbclient.dumpDb(pentest["nom"])
            dbclient.importDatabase(dbclient.getPentestOwner(pentest["nom"]), outpath, nsFrom=pentest["nom"], nsTo=pentest["uuid"])
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

def init_db():
    """Initialize empty databases or remaining tmp data from last run
    """
    dbclient = mongo.DBClient.getInstance()
    dbclient.deleteFromDb("pollenisator", "sockets", {}, many=True, notify=False)
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

def init_config():
    conf = loadServerConfig()
    port = int(os.environ.get("POLLENISATOR_PORT", conf.get("api_port", 5000)))
    https = os.environ.get("POLLENISATOR_SSL",conf.get("https", "false").lower() == "true")
    if https:
        ssl_context = "adhoc"
    else:
        ssl_context = None
    return port

def run(flask_app, debug):
    sm = SocketManager.getInstance()
    port = init_config()
    init_db()
    try:
        sm.socketio.run(flask_app, host=os.environ.get("POLLENISATOR_BIND_IP", '0.0.0.0'), port=port,
                     debug=debug, use_reloader=False, )
    except KeyboardInterrupt:
        pass
    return sm.socketio