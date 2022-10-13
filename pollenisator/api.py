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
import logging

from pollenisator.server.permission import permission
logging.basicConfig(filename='error.log', level=logging.INFO,
                    format='[%(asctime)s][%(levelname)s] - %(funcName)s: %(message)s')

console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
# add the handler to the root logger
logging.getLogger('').addHandler(console)

from flask_cors import CORS
from getpass import getpass
from pollenisator.server.token import verifyToken, decode_token
from pollenisator.core.Components.Utils import JSONEncoder, loadServerConfig
from pollenisator.core.Components.SocketManager import SocketManager
from flask import request
import sys
import bcrypt
import json

from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.server.modules.Worker.worker import doDeleteWorker, removeWorkers, unregister
import connexion
from pathlib import Path
import ruamel.yaml

def load_modules(app, main_file):
    modules_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "./server/modules/")
    # Load modules
    yaml = ruamel.yaml.YAML()
    with open(main_file) as fp:
        specs = yaml.load(fp)
        for path in Path(modules_path).rglob('*.yaml'):
            print("LOADING MODULE "+str(path))
            with open(path) as fp2:
                module_specs = yaml.load(fp2)
                if "components" in module_specs and "schemas" in module_specs["components"]:
                    for i in module_specs["components"]["schemas"]:
                        specs["components"]["schemas"].update({i:module_specs["components"]["schemas"][i]})
                for i in module_specs["paths"]:
                    specs["paths"].update({i:module_specs["paths"][i]})
          
        with open('/tmp/bundled.yaml', 'w') as fw:
            yaml.dump(specs, fw)
            app.add_api('/tmp/bundled.yaml')
        

# Create the application instance
server_folder = os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "./server/api_specs/")
app = connexion.App(__name__, specification_dir=server_folder, debug=debug)

# Create a URL route in our application for "/"

@app.route('/')
def home():
    """
    just check status
    """
    return "Api working"


def createWorker():
    salt = bcrypt.gensalt()
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.insertInDb("pollenisator", "users", {
                             "username": "Worker", "hash": bcrypt.hashpw("".encode(), salt), "scope": ["worker"]})


def createAdmin(username="", password=""):
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
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.insertInDb("pollenisator", "users", {"username": username, "hash": bcrypt.hashpw(
        password.encode(), salt), "scope": ["admin", "user"]})
    print("Administrator created")


def notify_clients(notif):
    """Notify clients websockets
    """
    mongoInstance = MongoCalendar.getInstance()
    sm = SocketManager.getInstance()
    sockets = mongoInstance.findInDb("pollenisator","sockets",{}, True)
    if notif["db"] == "pollenisator":
        sm.socketio.emit("notif", json.dumps(notif, cls=JSONEncoder))
    else:
        for socket in sockets:
            if socket["pentest"] == notif["db"]:
                sm.socketio.emit("notif", json.dumps(notif, cls=JSONEncoder), to=socket["sid"])


def init():
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.deleteFromDb("pollenisator", "sockets", {}, many=True, notify=False)
    any_user = mongoInstance.findInDb("pollenisator", "users", {}, False)
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
        createWorker()
    removeWorkers()
    conf = loadServerConfig()
    port = int(conf.get("api_port", 5000))
    https = conf.get("https", "false").lower() == "true"
    if https:
        ssl_context = "adhoc"
    else:
        ssl_context = None
    return port

def main():
    # Read the openapi.yaml file to configure the endpoints
    print("LOADING MAIN API")
    #app.add_api('openapi.yaml')
    load_modules(app, os.path.join(server_folder,"openapi.yaml"))

    flask_app = app.app
    sm = SocketManager.getInstance()

    sm.socketio.init_app(flask_app, log_output=False, logger=False,
                    engineio_logger=False, async_mode=async_mode)
    
    @sm.socketio.event
    def register(data):
        mongoInstance = MongoCalendar.getInstance()
        workerName = data.get("name")
        socket = mongoInstance.findInDb("pollenisator","sockets", {"user":workerName}, False)
        if socket is None:
            mongoInstance.insertInDb("pollenisator", "sockets", {"sid":request.sid, "user":workerName, "pentest":""}, notify=False)
        else:
            mongoInstance.updateInDb("pollenisator", "sockets", {"user":workerName}, {"$set":{"sid":request.sid, "pentest":""}}, notify=False)
        mongoInstance.registerWorker(workerName)

    @sm.socketio.event
    def registerForNotifications(data):
        sid = request.sid
        token = str(data.get("token", ""))
        pentest = str(data.get("pentest", ""))
        res = verifyToken(token)
        token_info = decode_token(token)
        if res:
            if pentest in token_info["scope"]:
                mongoInstance = MongoCalendar.getInstance()
                socket = mongoInstance.findInDb("pollenisator", "sockets", {"sid":sid}, False)
                if socket is None:
                    mongoInstance.insertInDb("pollenisator", "sockets", {"sid":sid, "pentest":pentest}, False)
                else:
                    mongoInstance.updateInDb("pollenisator", "sockets", {"sid":sid}, {"$set":{"pentest":pentest}}, notify=False)
            

    @sm.socketio.event
    def disconnect():
        sid = request.sid
        todel = None
        mongoInstance = MongoCalendar.getInstance()
        todel = mongoInstance.findInDb("pollenisator", "sockets", {"sid":sid}, False)
        if todel:
            unregister(todel)
            mongoInstance.deleteFromDb("pollenisator", "sockets", {"sid":sid}, False)

    # Tell your app object which encoder to use to create JSON from objects.
    flask_app.json_encoder = JSONEncoder
    CORS(flask_app)
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
