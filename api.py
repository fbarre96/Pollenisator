import connexion
from core.Components.mongo import MongoCalendar
import json
import os
import bcrypt
import sys
from datetime import datetime
from flask import jsonify, session
from bson import ObjectId
import threading
from core.Components.Utils import JSONEncoder, loadServerConfig
from server.worker import removeInactiveWorkers
from server.token import generateNewToken
from getpass import getpass
from flask_socketio import SocketIO
# Create the application instance
server_folder = os.path.join(os.path.dirname(os.path.realpath(__file__)), "./server/api_specs/")
app = connexion.App(__name__, specification_dir=server_folder)

# Read the openapi.yaml file to configure the endpoints
app.add_api('openapi.yaml')
flask_app = app.app
socketio = SocketIO(flask_app)

# Tell your app object which encoder to use to create JSON from objects. 
flask_app.json_encoder = JSONEncoder
# Create a URL route in our application for "/"

@app.route('/')
def home():
    """
    This function just responds to the browser ULR
    localhost:5000/ with a string "Api working"
    """
    return "Api working"

def removeInactiveWorkersTimerSet():
    removeInactiveWorkers()
    removeInactiveWorkersTimer = threading.Timer(
            30, removeInactiveWorkersTimerSet)
    removeInactiveWorkersTimer.start()

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
    mongoInstance.insertInDb("pollenisator", "users", {"username":username, "hash":bcrypt.hashpw(password.encode(), salt), "scope":["admin","user"]})
    print("Administrator created")

def notify_clients(notif):
    """Notify clients websockets
    """
    #HACK: connexion has a known issue with flask_socketio https://github.com/zalando/connexion/issues/832
    # it opens and close the server manytime resulting in losing the connection clients 
    # This loads the memory address of the socketio object from a file with ctypes !!!
    import _ctypes, json
    with open('socket-io.json') as json_file:
        data = json.load(json_file)
    socketio = _ctypes.PyObj_FromPtr(int(data['id']))
    socketio.emit("notif", json.dumps(notif, cls=JSONEncoder))

@socketio.event
def connect():
    """Called when a websocket client connects to the server
    """
    #HACK: connexion has a known issue with flask_socketio https://github.com/zalando/connexion/issues/832
    # it opens and close the server manytime resulting in losing the connection clients 
    # This saves the memory address of the socketio object to a file !!!
    # Another solution would be to store it in a global flask config current_app.config['socketio'] = socketio 
    # this does not seem to be stored across those modules
    with open('socket-io.json', "w") as json_file:
        json_file.write(json.dumps({"id":id(socketio)}))


# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    mongoInstance = MongoCalendar.getInstance()
    any_user = mongoInstance.findInDb("pollenisator", "users", {}, False)
    noninteractive = False
    if any_user is None:
        for arg in sys.argv:
            if arg == "-h" or "--help":
                print("""Usage : python api.py [-h|--help] [--non-interactive]
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
        
    removeInactiveWorkersTimer = threading.Timer(
            30, removeInactiveWorkersTimerSet)
    removeInactiveWorkersTimer.start()
    conf = loadServerConfig()
    port = int(conf.get("api_port", 5000))
    https = conf.get("https", "false").lower() == "true"
    if https:
        ssl_context = "adhoc"
    else:
        ssl_context = None
    socketio.run(flask_app, host='0.0.0.0', port=port, debug=True)
    removeInactiveWorkersTimer.cancel()

