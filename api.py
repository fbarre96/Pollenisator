import connexion
from core.Components.mongo import MongoCalendar
import json
from datetime import datetime
from flask import jsonify
from bson import ObjectId
import threading
from core.Components.Utils import JSONEncoder

# Create the application instance
app = connexion.App(__name__, specification_dir='./server/api_specs/')

# Read the swagger.yaml file to configure the endpoints
app.add_api('swagger.yaml')
# Tell your app object which encoder to use to create JSON from objects. 
app.app.json_encoder = JSONEncoder
# Create a URL route in our application for "/"
@app.route('/')
def home():
    """
    This function just responds to the browser ULR
    localhost:5000/
    :return:        the rendered template 'home.html'
    """
    return "Api working"

def removeInactiveWorkers():
    mongoInstance.removeInactiveWorkers()
    removeInactiveWorkersTimer = threading.Timer(
            30, removeInactiveWorkers)
    removeInactiveWorkersTimer.start()

# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    mongoInstance = MongoCalendar.getInstance()
    removeInactiveWorkersTimer = threading.Timer(
            30, removeInactiveWorkers)
    removeInactiveWorkersTimer.start()
    #import logging
    #logging.basicConfig(filename='error.log',level=logging.DEBUG)
    app.run(host='0.0.0.0', port=5000, debug=True)
    removeInactiveWorkersTimer.cancel()
