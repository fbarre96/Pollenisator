import connexion
from core.Components.mongo import MongoCalendar
import json
import os
import bcrypt
from datetime import datetime
from flask import jsonify, session
from bson import ObjectId
import threading
from core.Components.Utils import JSONEncoder, loadServerConfig
from server.worker import removeInactiveWorkers
from server.token import generateNewToken
from getpass import getpass
#from server.NotificationService import NotificationService
# Create the application instance
server_folder = os.path.join(os.path.dirname(os.path.realpath(__file__)), "./server/api_specs/")
app = connexion.App(__name__, specification_dir=server_folder)

# Read the openapi.yaml file to configure the endpoints
app.add_api('openapi.yaml')
flask_app = app.app
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

def createAdmin():
    print("The user database is empty, create an admin now")
    username = input("username: ")
    while username.strip() == "":
        print("username cannot be empty")
        username = input("username: ")
    password = getpass("password: ")
    while password.strip() == "":
        print("Password cannot be empty")
        password = getpass("password: ")
    salt = bcrypt.gensalt()
    mongoInstance.insertInDb("pollenisator", "users", {"username":username, "hash":bcrypt.hashpw(password.encode(), salt), "scope":["admin","user"]})
    print("Administrator created")


# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    mongoInstance = MongoCalendar.getInstance()
    any_user = mongoInstance.findInDb("pollenisator", "users", {}, False)
    if any_user is None:
        createAdmin()
        
    removeInactiveWorkersTimer = threading.Timer(
            30, removeInactiveWorkersTimerSet)
    removeInactiveWorkersTimer.start()
    #import logging
    #logging.basicConfig(filename='error.log',level=logging.DEBUG)
    conf = loadServerConfig()
    port = int(conf.get("api_port", 5000))
    https = conf.get("https", "false").lower() == "true"
    if https:
        ssl_context = "adhoc"
    else:
        ssl_context = None
    #notif_service = NotificationService()
    #notif_service.start()
    with flask_app.app_context():
        app.run(host='0.0.0.0', port=port, debug=True, ssl_context=ssl_context)

    removeInactiveWorkersTimer.cancel()
