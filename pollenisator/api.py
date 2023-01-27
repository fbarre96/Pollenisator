# ENABLE debug mode early because evenlet monkey patch other libs
import os
debug = os.environ.get("FLASK_DEBUG", False)
if debug:
    async_mode = "threading" # Be aware thats sockets does not seems to work when debugging
else:
    import eventlet
    eventlet.monkey_patch()
    async_mode = "eventlet"
    
# ENABLE LOGGING EARLY ON
from pollenisator.core.components.logger_config import logger

from pollenisator.server.permission import permission


from flask_cors import CORS
from getpass import getpass
from bson import ObjectId
from pollenisator.server.token import verifyToken, decode_token
from pollenisator.core.components.utils import JSONEncoder, loadServerConfig
from pollenisator.core.components.socketmanager import SocketManager
from pollenisator.server.modules.worker.worker import doSetInclusion
from flask import request
import sys
import bcrypt
import json

from pollenisator.core.components.mongo import DBClient
from pollenisator.server.modules.worker.worker import removeWorkers, unregister
import connexion
from pathlib import Path
import ruamel.yaml
from ruamel.yaml.comments import CommentedSeq, CommentedMap
from collections import OrderedDict

# Create the application instance
server_folder = os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "./server/api_specs/")
app = connexion.App(__name__, specification_dir=server_folder, debug=debug)
flask_app = app.app
loaded = False
# Create a URL route in our application for "/"

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
        



@app.route('/')
def home():
    """Returns a simple message to indicate that the API is working.
    """
    return "Api working"


def createAdmin(username="", password=""):
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
    dbclient = DBClient.getInstance()
    dbclient.insertInDb("pollenisator", "users", {"username": username, "hash": bcrypt.hashpw(
        password.encode(), salt), "scope": ["admin", "user"]})
    print("Administrator created")


def notify_clients(notif):
    """Notify clients websockets
    """
    dbclient = DBClient.getInstance()
    sm = SocketManager.getInstance()
    sockets = dbclient.findInDb("pollenisator","sockets",{}, True)
    if notif["db"] == "pollenisator":
        sm.socketio.emit("notif", json.dumps(notif, cls=JSONEncoder))
    else:
        for socket in sockets:
            if socket["pentest"] == notif["db"]:
                sm.socketio.emit("notif", json.dumps(notif, cls=JSONEncoder), to=socket["sid"])


def init():
    """Initialize empty databases or remaining tmp data from last run
    """
    dbclient = DBClient.getInstance()
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
            createAdmin("admin", "admin")
        else:
            createAdmin()
        #createWorker()
    removeWorkers()
    dbclient.resetRunningTools()
    conf = loadServerConfig()
    port = int(conf.get("api_port", 5000))
    https = conf.get("https", "false").lower() == "true"
    if https:
        ssl_context = "adhoc"
    else:
        ssl_context = None
    return port


def create_app():
    """Loads all API ymal modules and init the App with SocketIO + Connexion + Flask
    """
    # Read the openapi.yaml file to configure the endpoints
    logger.info("LOADING MAIN API")
    if not loaded:
        load_modules(app, os.path.join(server_folder,"openapi.yaml"))

    flask_app = app.app
    sm = SocketManager.getInstance()
    logger.info('Running')
    sm.socketio.init_app(flask_app, log_output=False, logger=False,
                    engineio_logger=False, async_mode=async_mode)
    
    @sm.socketio.event
    def register(data):
        """Registers a worker and associates it with a socket.

        Args:
            data: A dictionary containing the worker's name and list of supported binaries.
        """
        dbclient = DBClient.getInstance()
        workerName = data.get("name")
        binaries = data.get("binaries", [])
        
        socket = dbclient.findInDb("pollenisator","sockets", {"user":workerName}, False)
        if socket is None:
            dbclient.insertInDb("pollenisator", "sockets", {"sid":request.sid, "user":workerName, "pentest":""}, notify=False)
        else:
            dbclient.updateInDb("pollenisator", "sockets", {"user":workerName}, {"$set":{"sid":request.sid, "pentest":""}}, notify=False)
        dbclient.registerWorker(workerName, binaries)

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
        sid = request.sid
        token = str(data.get("token", ""))
        pentest = str(data.get("pentest", ""))
        res = verifyToken(token)
        token_info = decode_token(token)
        if res:
            if pentest in token_info["scope"]:
                dbclient = DBClient.getInstance()
                socket = dbclient.findInDb("pollenisator", "sockets", {"sid":sid}, False)
                if socket is None:
                    dbclient.insertInDb("pollenisator", "sockets", {"sid":sid, "pentest":pentest}, False)
                else:
                    dbclient.updateInDb("pollenisator", "sockets", {"sid":sid}, {"$set":{"pentest":pentest}}, notify=False)
    
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
        dbclient = DBClient.getInstance()        
        worker = dbclient.findInDb("pollenisator","workers", {"name":workerName}, False)
        if worker is None:
            sm.socketio.emit("deleteWorker", room=request.sid)
            return
        pentest = worker.get("pentest", "")
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
        dbclient = DBClient.getInstance()
        todel = dbclient.findInDb("pollenisator", "sockets", {"sid":sid}, False)
        if todel:
            unregister(todel.get("worker"))
            dbclient.deleteFromDb("pollenisator", "sockets", {"sid":sid}, False)

    flask_app.json_encoder = JSONEncoder
    CORS(flask_app)
    return flask_app


def main():
    """Create the app and run it
    """
    logger.info('MAIN')
    app = create_app()
    run(flask_app)
    
def run(flask_app):
    """Starts the API server.
    """
    sm = SocketManager.getInstance()
    port = init()
    try:
        sm.socketio.run(flask_app, host='0.0.0.0', port=port,
                     debug=debug, use_reloader=False, )
    except KeyboardInterrupt:
        pass
    return sm.socketio

# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    main()
