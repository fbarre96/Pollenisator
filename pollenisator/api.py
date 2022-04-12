# ENABLE debug mode early because evenlet monkey patch other libs
debug = True 
if debug:
    async_mode = "threading" # Be aware thats sockets does not seems to work when debugging
else:
    import eventlet
    eventlet.monkey_patch()
    async_mode = "eventlet"
    
# ENABLE LOGGING EARLY ON
import logging
logging.basicConfig(filename='error.log', level=logging.INFO,
                    format='[%(asctime)s][%(levelname)s] - %(funcName)s: %(message)s')

from flask_cors import CORS
from flask_socketio import SocketIO
from getpass import getpass
from pollenisator.server.worker import removeWorkers, unregister
from pollenisator.core.Components.Utils import JSONEncoder, loadServerConfig
from flask import request
import sys
import bcrypt
import os
import json
from pollenisator.core.Components.mongo import MongoCalendar
import connexion



sockets = {}

logger = logging.getLogger(__name__)
# Create the application instance
server_folder = os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "./server/api_specs/")
app = connexion.App(__name__, specification_dir=server_folder, debug=debug)
# Read the openapi.yaml file to configure the endpoints
app.add_api('openapi.yaml')
flask_app = app.app
socketio = SocketIO(logger=logger, engineio_logger=logger)

socketio.init_app(flask_app, log_output=False, logger=False,
                  engineio_logger=False, async_mode=async_mode)
# Tell your app object which encoder to use to create JSON from objects.
flask_app.json_encoder = JSONEncoder
CORS(flask_app)
# Create a URL route in our application for "/"


@app.route('/')
def home():
    """
    This function just responds to the browser ULR
    localhost:5000/ with a string "Api working"
    """
    return "Api working"


def createWorker():
    salt = bcrypt.gensalt()
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.insertInDb("pollenisator", "users", {
                             "username": "Worker", "hash": bcrypt.hashpw("", salt), "scope": ["worker"]})
    print("Worker created")


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
    global socketio
    socketio.emit("notif", json.dumps(notif, cls=JSONEncoder))


@socketio.event
def registerCommands(data):
    mongoInstance = MongoCalendar.getInstance()
    workerName = data.get("workerName")
    tools = data.get("tools")
    global sockets
    sockets[workerName] = request.sid
    command_names = tools
    mongoInstance.registerCommands(workerName, command_names)


@socketio.event
def register(data):
    mongoInstance = MongoCalendar.getInstance()
    workerName = data.get("workerName")
    global sockets
    sockets[workerName] = request.sid
    mongoInstance.registerWorker(workerName)


@socketio.event
def disconnect():
    sid = request.sid
    todel = None
    global sockets
    for key, val in sockets.items():
        if val == sid:
            todel = key
    if todel:
        unregister(todel)
        del sockets[todel]


def main():
    mongoInstance = MongoCalendar.getInstance()
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
    try:
        socketio.run(flask_app, host='0.0.0.0', port=port,
                     debug=debug, use_reloader=False, )
    except KeyboardInterrupt:
        pass
    return socketio


# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    main()
