import connexion
from core.Components.mongo import MongoCalendar
import json
import bcrypt
from datetime import datetime
from flask import jsonify
from bson import ObjectId
import threading
from core.Components.Utils import JSONEncoder
from server.worker import removeInactiveWorkers
from server.token import generateNewToken
from getpass import getpass
# Create the application instance
app = connexion.App(__name__, specification_dir='./server/api_specs/')

# Read the openapi.yaml file to configure the endpoints
app.add_api('openapi.yaml')
# Tell your app object which encoder to use to create JSON from objects. 
app.app.json_encoder = JSONEncoder
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
    app.run(host='0.0.0.0', port=5000, debug=True)
    removeInactiveWorkersTimer.cancel()
