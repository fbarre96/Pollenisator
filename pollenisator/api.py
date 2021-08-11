import connexion
from pollenisator.core.Components.mongo import MongoCalendar
import json
import os
import bcrypt
import sys
from datetime import datetime
from flask import jsonify, session
from bson import ObjectId
import threading
from pollenisator.core.Components.Utils import JSONEncoder, loadServerConfig
from pollenisator.server.worker import removeInactiveWorkers
from pollenisator.server.token import generateNewToken
from getpass import getpass
from flask_socketio import SocketIO
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] - %(funcName)s: %(message)s')
logger = logging.getLogger(__name__)
# Create the application instance
server_folder = os.path.join(os.path.dirname(os.path.realpath(__file__)), "./server/api_specs/")
app = connexion.App(__name__, specification_dir=server_folder, debug=True)

# Read the openapi.yaml file to configure the endpoints
app.add_api('openapi.yaml')
flask_app = app.app
socketio = SocketIO(logger=logger, engineio_logger=logger) 
socketio.init_app(flask_app, log_output=False, logger=False, engineio_logger=False)
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
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.insertInDb("pollenisator", "users", {"username":username, "hash":bcrypt.hashpw(password.encode(), salt), "scope":["admin","user"]})
    print("Administrator created")

def notify_clients(notif):
    """Notify clients websockets
    """
    global socketio
    socketio.emit("notif", json.dumps(notif, cls=JSONEncoder))


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
    flask_app.config["DEBUG"] = True
    try:
        socketio.run(flask_app, host='0.0.0.0', port=port, debug=True, use_reloader=False)
    except KeyboardInterrupt:
        pass
    removeInactiveWorkersTimer.cancel()



# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    main()