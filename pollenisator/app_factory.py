"""
This module contains the main application factory for the Pollenisator server.
"""
import os
import sys
from typing import Dict, Any
from getpass import getpass
from pathlib import Path
import json
import connexion.jsonifier
import ruamel.yaml
import connexion
import time
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
from pollenisator.migrate import migrate
from pollenisator.server.permission import checkPentestPermission
from pollenisator.server.modules.worker.worker import doSetInclusion

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


def handle_start_terminal_session(sm: SocketManager, data: Dict[str, Any], socket: Dict[str, Any], dbclient: mongo.DBClient, request_sid: str) -> None:
    existing_session = dbclient.findInDb(socket["pentest"], "terminalsessions", {"user":socket["user"], "id":data.get("id")}, False)
    if existing_session is not None:
        for output_log in existing_session.get("logs", []):
            sm.socketio.emit("proxy-term", {"action":"pty-output", "id":data.get("id"), "output":output_log}, room=request_sid)
    else:
        dbclient.insertInDb(socket["pentest"], "terminalsessions", {"user":socket["user"], "id":data.get("id"), "name":data.get("name"), "target_check_iid":data.get("target_check_iid",None), "visible_target":data.get("visible_target",None), "target_tools_iids": data.get("target_tools_iids", []),"logs":[], "status":"open", "displayMode": data.get("displayMode", "panel"), "time_created":int(time.time())})

def handle_stop_terminal_session(sm: SocketManager, data: Dict[str, Any], socket: Dict[str, Any], dbclient: mongo.DBClient, request_sid: str) -> None:
    existing_session = dbclient.findInDb(socket["pentest"], "terminalsessions", {"user":socket["user"], "id":data.get("id")}, False)
    if existing_session is not None:
        dbclient.updateInDb(socket["pentest"], "terminalsessions", { "id":data.get("id")}, {"$set":{"status":"closed"}}, False)
    
def handle_pty_output(sm: SocketManager, data: Dict[str, Any], socket: Dict[str, Any], dbclient: mongo.DBClient) -> None:
    existing_session = dbclient.findInDb(socket["pentest"], "terminalsessions", {"user":socket["user"], "id":data.get("id")}, False)
    if existing_session is not None:
        dbclient.updateInDb(socket["pentest"], "terminalsessions", {"user":socket["user"], "id":data.get("id")}, {"$push":{"logs":data.get("output")}}, False, False)

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
    connexion.jsonifier.JSONEncoder = JSONEncoder
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
    allowed_properties = {
        "defects":["synthesis","impacts", "description"],
        "defectsreviews" : ["synthesis","impacts", "description"],
        "documents":["data"]
    }
    collections_doc_id = {
        "defectsreviews": "defect_iid"
    }
    @sm.socketio.event
    def register(data):
        """Registers a worker and associates it with a socket.

        Args:
            data: A dictionary containing the worker's name and list of supported binaries.
        """
        dbclient = mongo.DBClient.getInstance()
        workerName = data.get("name")
        sid = request.sid
        logger.info("Registering socket as worker %s", sid)

        supported_plugins = data.get("supported_plugins", [])
        socket = dbclient.findInDb("pollenisator","sockets", {"user":workerName, "type":"worker"}, False)
        if socket is None:
            dbclient.insertInDb("pollenisator", "sockets", {"sid":request.sid, "user":workerName, "type":"worker", "pentest":""}, notify=False)
        else:
            dbclient.updateInDb("pollenisator", "sockets", {"user":workerName, "type":"worker"}, {"$set":{"sid":request.sid, "pentest":""}}, notify=False)
        dbclient.registerWorker(workerName, supported_plugins)

    @sm.socketio.event
    def registerAsTerminalWorker(data):
        """Registers a terminal worker and associates it with a socket.

        Args:
            data: A dictionary containing the terminal's name.
        """
        from pollenisator.server.token import verifyToken, decode_token
        dbclient = mongo.DBClient.getInstance()
        token = str(request.cookies.get("session_token", ""))
        if token == "":
            logger.info("No session token found in cookies")
        token = data.get("token", token)
        if token == "":
            logger.error("No session token found in data neither")
            return
        logger.info("Registering terminal worker with token %s", token)
        pentest = data.get("pentest", "")
        supported_plugins = data.get("supported_plugins", [])
        sid = request.sid
        res = verifyToken(token)
        if res:
            token_info = decode_token(token)
            user = dbclient.findInDb("pollenisator", "users", {"token":token}, False)
            if user is None:
                return
            username = user.get("username", None)
            if username is None:
                return
            logger.info("Registering terminal worker for user %s", str(username))
            if checkPentestPermission(token_info, pentest, False):
                dbclient = mongo.DBClient.getInstance()
                socket = dbclient.findInDb("pollenisator", "sockets", {"sid":sid, "user":username, "type":"terminal"}, False)
                if socket is None:
                    dbclient.insertInDb("pollenisator", "sockets", {"sid":sid, "user":username, "type":"terminal", "pentest":pentest, "supported_plugins":supported_plugins}, False)
                else:
                    dbclient.updateInDb("pollenisator", "sockets", {"sid":sid, "user":username}, {"$set":{"pentest":pentest, "user":username, "supported_plugins":supported_plugins}}, notify=False)
                #sm.socketio.emit("testTerminal", {"pentest":pentest}, room=request.sid)
                register(data)
                workerName = data.get("name")
                doSetInclusion(workerName, pentest, True)
                
                socket_terminal_consumer = dbclient.findInDb("pollenisator", "sockets", {"user":username, "type":"terminalConsumer"}, False)
                if socket_terminal_consumer is not None:
                    logger.info("sending pollterminal_connected to consumer")
                    sm.socketio.emit("pollterminal_connected", {"pentest":pentest , "supported_plugins":supported_plugins}, room=socket_terminal_consumer["sid"])
                    sm.socketio.emit("consumer_connected", {"pentest":pentest}, room=request.sid)
                    dbclient.updateInDb("pollenisator", "sockets", {"user":username, "type":"terminal"}, {"$set":{"consumer_sid":socket_terminal_consumer["sid"]}}, notify=False)
                    dbclient.updateInDb("pollenisator", "sockets", {"user":username, "type":"terminalConsumer"}, {"$set":{"worker_sid":request.sid}}, notify=False)
    @sm.socketio.event
    def registerAsTerminalConsumer(data):
        from pollenisator.server.token import verifyToken, decode_token
        logger.info("received registerAsTerminalConsumer")
        dbclient = mongo.DBClient.getInstance()
        token = str(request.cookies.get("session_token", ""))
        pentest = data.get("pentest", "")
        sid = request.sid
        res = verifyToken(token)
        logger.info("Registering socket as terminal consumer %s", sid)
        if res:
            token_info = decode_token(token)
            user = dbclient.findInDb("pollenisator", "users", {"token":token}, False)
            if user is None:
                return
            username = user.get("username", None)
            if username is None:
                return
            logger.info("Registering terminal consumer for user %s", str(username))
            if checkPentestPermission(token_info, pentest, False):
                dbclient = mongo.DBClient.getInstance()
                socket = dbclient.findInDb("pollenisator", "sockets", {"sid":sid, "user":username, "type":"terminalConsumer"}, False)
                if socket is None:
                    dbclient.insertInDb("pollenisator", "sockets", {"sid":sid, "user":username, "type":"terminalConsumer", "pentest":pentest}, False)
                else:
                    dbclient.updateInDb("pollenisator", "sockets", {"sid":sid, "user":username }, {"$set":{"pentest":pentest , "user":username}}, notify=False)
                #sm.socketio.emit("testTerminalConsumer", {"pentest":pentest}, room=request.sid)
            socket_terminal_worker = dbclient.findInDb("pollenisator", "sockets", {"user":username, "type":"terminal"}, False)
            if socket_terminal_worker is not None:
                logger.info("sending pollterminal_connected to consumer")
                sm.socketio.emit("pollterminal_connected", {"pentest":pentest, "supported_plugins":socket_terminal_worker.get("supported_plugins", [])}, room=sid)
                sm.socketio.emit("consumer_connected", {"pentest":pentest}, room=socket_terminal_worker["sid"])
                dbclient.updateInDb("pollenisator", "sockets", {"user":username, "type":"terminal"}, {"$set":{"consumer_sid":sid}}, notify=False)
                dbclient.updateInDb("pollenisator", "sockets", {"user":username, "type":"terminalConsumer"}, {"$set":{"worker_sid":socket_terminal_worker["sid"]}}, notify=False)
    @sm.socketio.event
    def registerForNotifications(data):
        """Register the socket for notifications for a specific pentest.

            Args:
                data (dict): A dictionary containing the following keys:
                    - "pentest" (str): The ID of the pentest for which the socket wants to receive notifications.

            Returns:
                None
        """
        from pollenisator.server.token import verifyToken, decode_token
        logger.info("Registering socket for notifications %s", str(data))
        sid = request.sid
        token = str(request.cookies.get("session_token", ""))
        pentest = str(data.get("pentest", ""))
        res = verifyToken(token)
        if res:
            token_info = decode_token(token)
            if checkPentestPermission(token_info, pentest, False):
                dbclient = mongo.DBClient.getInstance()
                socket = dbclient.findInDb("pollenisator", "sockets", {"sid":sid}, False)
                if socket is None:
                    dbclient.insertInDb("pollenisator", "sockets", {"sid":sid, "pentest":pentest}, False)
                else:
                    dbclient.updateInDb("pollenisator", "sockets", {"sid":sid}, {"$set":{"pentest":pentest}}, notify=False)
                    leave_room(socket["pentest"], sid)
                join_room(pentest, sid)
                sm.socketio.emit("accepted-register", {"message":"Socket registered for notifications"}, room=request.sid)
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
        logger.info("Disconnecting socket %s", sid)
        sockets = dbclient.findInDb("pollenisator", "sockets", {"sid":sid}, True)
        if sockets:
            for todel in sockets:
                if todel.get("type") == "terminal":
                    if todel.get("consumer_sid") is not None:
                        sm.socketio.emit("pollterminal_disconnected", {"pentest":todel["pentest"]}, room=todel["consumer_sid"])
                        dbclient.updateInDb("pollenisator", "sockets", {"sid":todel["consumer_sid"]}, {"$unset":{"worker_sid":""}})
                elif todel.get("type") == "terminalConsumer":
                    if todel.get("worker_sid") is not None:
                        sm.socketio.emit("consumer_disconnected", {"pentest":todel["pentest"]}, room=todel["worker_sid"])
                        dbclient.updateInDb("pollenisator", "sockets", {"sid":todel["worker_sid"]}, {"$unset":{"consumer_sid":""}})
                else:
                    unregister(todel.get("user"))
            dbclient.deleteFromDb("pollenisator", "sockets", {"sid":sid}, True)

    @sm.socketio.event
    def test(data):
        logger.info("TEST received : %s", str(data))
        logger.debug(data)
        sm.socketio.emit("test", {"test":"HELLO"}, room=request.sid)
        
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
        doc_id = data.get("doc_id","")
        logger.debug("Received demand for document %s", str(data))
        if doc_id == "":
            logger.debug("Document id not found because empty id%s", str(data))
            return {"error":"Document not found"}
        doc_collection = data.get("doc_collection","")
        doc_property = data.get("doc_property","")
        if doc_collection not in allowed_properties:
            return {"error":"Forbidden"}
        if doc_property not in allowed_properties[doc_collection]:
            return {"error":"Forbidden"}
        if doc_id == pentest:
            doc = dbclient.findInDb(pentest, "documents", {"pentest":pentest}, False)
            if doc is None:
                ins_result = dbclient.insertInDb(pentest, "documents", {"data":{}, "pentest":pentest})
                if ins_result is None:
                    logger.debug("Document could not be created %s", str(data))
                    return {"error": "Document could not be created"}
                res = ins_result.inserted_id
                doc = {}
            else:
                doc = {"data":doc.get("data", {})}
        else:
            doc = dbclient.findInDb(pentest, doc_collection, {collections_doc_id.get(doc_collection, "_id"):ObjectId(doc_id)}, False, use_cache=False)
            if doc is None:
                logger.debug("Document not found for pentest %s, collection %s, where %s = %s", str(pentest), str(doc_collection), str(collections_doc_id.get(doc_collection, "_id")), str(ObjectId(doc_id)))
                return {"error":"Document not found"}
            doc = {"data":doc.get(doc_property, "")}
        join_room(pentest, sid)
        logger.debug("Reply to for document %s is %s", str(data), str({"doc_id":str(doc_id),"doc_property":doc_property, "doc_collection":doc_collection, "data":doc.get("data", {})}))

        sm.socketio.emit("load-document", {"doc_id":str(doc_id),"doc_property":doc_property, "doc_collection":doc_collection, "data":doc.get("data", {})}, room=request.sid)

    @sm.socketio.on("send-delta")
    def send_delta_received(data):
        sid = request.sid
        dbclient = mongo.DBClient.getInstance()
        delta = data.get("delta", {})
        doc_id = data.get("doc_id", "")
        doc_collection = data.get("doc_collection", "")
        doc_property = data.get("doc_property", "")
        logger.debug("received delta %s", str(data))
        if doc_collection not in allowed_properties:
            return {"error":"Forbidden"}
        if doc_property not in allowed_properties[doc_collection]:
            return {"error":"Forbidden"}
        socket = dbclient.findInDb("pollenisator", "sockets", {"sid":sid}, False)
        if socket is None:
            return {"error":"Forbidden"}
        if socket["pentest"] == "":
            return {"error":"Forbidden"}
        pentest = socket["pentest"]
        sm.socketio.emit("received-delta", {"delta":delta, "doc_id":doc_id, "doc_collection":doc_collection, "doc_property":doc_property}, room=pentest, include_self=False)
   
    @sm.socketio.on("save-document")
    def save_document(data):
        dbclient = mongo.DBClient.getInstance()
        sid = request.sid
        doc_id = data.get("doc_id", "")
        doc_collection = data.get("doc_collection", "")
        doc_property = data.get("doc_property", "")
        document_data = data.get("document", "")
        logger.debug("Saving document %s", str(data))
        if doc_collection not in allowed_properties:
            return {"error":"Forbidden"}
        if doc_property not in allowed_properties[doc_collection]:
            return {"error":"Forbidden"}
        socket = dbclient.findInDb("pollenisator", "sockets", {"sid":sid}, False)
        if socket is None:
            return {"error":"Forbidden"}
        if socket["pentest"] == "":
            return {"error":"Forbidden"}
        pentest = socket["pentest"]
        if doc_id == pentest:
            dbclient.updateInDb(pentest, "documents", {"pentest":pentest}, {"$set":{"data":document_data}})
        else:
            dbclient.updateInDb(pentest, doc_collection, {collections_doc_id.get(doc_collection, "_id"):ObjectId(doc_id)}, {"$set":{doc_property: document_data}})

    @sm.socketio.on("proxy-term")
    def proxy_terminal(data):
        dbclient = mongo.DBClient.getInstance()
        socket = dbclient.findInDb("pollenisator", "sockets", {"sid":request.sid, "type":{"$in":["terminalConsumer","terminal"]}}, False)
        #logger.info("Receiving proxy-term %s on socket %s", str(data), str(socket))
        if socket is None:
            logger.error("Socket not found %s", str(data))
            return {"error":"Forbidden"}
        if socket["pentest"] == "":
            logger.error("Socket not connected to a pentest %s", str(data))
            return {"error":"Forbidden"}
        
        action = data.get("action", "")
        if action == "start-terminal-session":
            handle_start_terminal_session(sm, data, socket, dbclient, request.sid)
        elif action == "stop-terminal-session":
            handle_stop_terminal_session(sm, data, socket, dbclient, request.sid)
        elif action == "pty-output":
            handle_pty_output(sm, data, socket, dbclient)
        #logger.info("Receiving proxy-term %s", str(data))
        if socket["type"] == "terminalConsumer":
            if socket.get("worker_sid") is None:
                logger.error("Socket not connected to a worker %s", str(data))
                return {"error":"Forbidden"}
            sm.socketio.emit("proxy-term", data, room=socket["worker_sid"])
        elif socket["type"] == "terminal":
            if socket.get("consumer_sid") is None:
                logger.error("Socket not connected to a consumer %s", str(socket))
                return {"error":"Forbidden"}
            sm.socketio.emit("proxy-term", data, room=socket["consumer_sid"])

    flask_app.json_encoder = JSONEncoder
    logger.info('Running ...')
    CORS(flask_app,  expose_headers= ['Content-Disposition'])
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

def add_default_admin_if_needed(dbclient: mongo.DBClient) -> None:
    """Check if there is at least one user in the database, if not create an admin user."""
    any_user = dbclient.findInDb("pollenisator", "users", {}, False)
    noninteractive = False
    if any_user is None:
        for arg in sys.argv:
            if arg == "-h" or arg == "--help":
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

def init_db() -> None:
    """
    Initialize empty databases or remaining tmp data from the last run.

    This function connects to the database, deletes any remaining socket data, checks for existing users, and creates an admin user if none exist. It also handles command-line arguments for non-interactive mode and help. Finally, it performs database migration and removes any remaining workers.
    """
    dbclient = mongo.DBClient.getInstance()
    dbclient.deleteFromDb("pollenisator", "sockets", {}, many=True, notify=False)
    res = dbclient.findInDb("pollenisator", "settings", {}, True)
    settings = [] if res is None else [s for s in res]
    if len(settings) < 2 or settings[0].get("key") != "pentest_types" or settings[1].get("key") != "tags":
        dbclient.insertInDb("pollenisator", "settings", {"key":"pentest_types", "value":'{"Web": ["Base", "Application", "Data", "Policy"], "LAN": ["Base", "Application", "Infrastructure", "Active Directory", "Data", "Policy"]}'})
        dbclient.insertInDb("pollenisator", "settings", {"key":"tags", "value":'{"todo": {"color": "orange", "level": "todo"}, "pwned": {"color": "red", "level": "high"}, "Interesting": {"color": "dark green", "level": "medium"}, "Uninteresting": {"color": "sky blue", "level": "low"}, "neutral": {"color": "transparent", "level": ""}}'})
        dbclient.insertInDb("pollenisator", "settings", {"key":"defect_notation_types", "value":'["CVSS"]'})
    add_default_admin_if_needed(dbclient)
    migrate()
    removeWorkers()

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