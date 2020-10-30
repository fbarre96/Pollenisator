import json
import requests
import os
import core.Components.Utils as Utils
from bson import ObjectId
from core.Components.Utils import JSONEncoder, JSONDecoder

proxies = {"http":"127.0.0.1:8080", "https":"127.0.0.1:8080"}
dir_path = os.path.dirname(os.path.realpath(__file__))  # fullpath to this file
config_dir = os.path.join(dir_path, "./../../config/")
if not os.path.isfile(os.path.join(config_dir, "client.cfg")):
    if os.path.isfile(os.path.join(config_dir, "clientSample.cfg")):
        copyfile(os.path.join(config_dir, "clientSample.cfg"), os.path.join(config_dir, "client.cfg"))

if os.path.isfile(os.path.join(config_dir, "client.cfg")):
    cfg = Utils.loadCfg(os.path.join(config_dir, "client.cfg"))
else:
    print("No client config file found under "+str(config_dir))
    sys.exit(1)



class APIClient():
    __instances = dict()

    @staticmethod
    def getInstance():
        """ Singleton Static access method.
        """
        pid = os.getpid()  # HACK : One api client per process.
        instance = APIClient.__instances.get(pid, None)
        if instance is None:
            APIClient()
        return APIClient.__instances[pid]

    def __init__(self):
        pid = os.getpid()  # HACK : One mongo per process.
        if APIClient.__instances.get(pid, None) is not None:
            raise Exception("This class is a singleton!")
        self.currentPentest = None
        self._observers = []
        APIClient.__instances[pid] = self
        self.headers = {'Content-Type': 'application/json'}
        self.api_url_base = "http://"+cfg["host"]+":"+str(cfg["port"])+"/api/v1/"

    def tryConnection(self, config=cfg):
        response = requests.get(self.api_url_base, headers=self.headers)
        return response.status_code == 200
    
    def setCurrentPentest(self, newCurrentPentest):
        self.currentPentest = newCurrentPentest
        

    def getCurrentPentest(self):
        return self.currentPentest

    def removeInactiveWorkers(self):
        
        api_url = '{0}workers/removeInactiveWorkers'.format(self.api_url_base)
        response = requests.get(api_url, headers=self.headers)
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None

    def getRegisteredCommands(self, workerName):
        api_url = '{0}workers/{1}/getRegisteredCommands/'.format(self.api_url_base, workerName)
        response = requests.get(api_url, headers=self.headers)
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None

    def registeredCommands(self, workerName, commandNames):
        api_url = '{0}workers/{1}/registerCommands/'.format(self.api_url_base, workerName)
        response = requests.put(api_url, headers=self.headers, data={"command_names":commandNames})
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None

    def reinitConnection(self):
        self.setCurrentPentest("")

    def attach(self, observer):
        """
        Attach an observer to the database. All attached observers will be notified when a modication is done to a calendar through the methods presented below.

        Args:
            observer: the observer that implements a notify(collection, iid, action) function
        """
        self._observers.append(observer)

    def dettach(self, observer):
        """
        Dettach the given observer from the database.

        Args:
            observer: the observer to detach
        """
        try:
            self._observers.remove(observer)
        except ValueError:
            pass

    def pushNotification(self, pentest, collection, iid, action, parentId=""):
        api_url = '{0}notification'.format(self.api_url_base)
        response = requests.post(api_url, headers=self.headers, data={"db":pentest, "collection":colletion, "iid":iid, "action":action, "parentId":parentId})
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None

    def fetchNotifications(self, pentest, fromTime):
        api_url = '{0}notification/{1}'.format(self.api_url_base, pentest)
        response = requests.get(api_url, headers=self.headers, params={"fromTime":fromTime})
        if response.status_code == 200:
            notifications = json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
            return notifications
        else:
            return []

    def getPentestList(self):
        api_url = '{0}pentests'.format(self.api_url_base)
        response = requests.get(api_url, headers=self.headers)
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None
    
    def doDeletePentest(self, pentest):
        api_url = '{0}pentest/{1}'.format(self.api_url_base, pentest)
        response = requests.delete(api_url, headers=self.headers)
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None

    def registerPentest(self, pentest):
        api_url = '{0}pentest/{1}'.format(self.api_url_base, pentest)
        response = requests.post(api_url, headers=self.headers)
        if response.status_code == 200:
            return True
        else:
            return False

    def find(self, collection, pipeline=None, multi=True):
        return self.findInDb(self.getCurrentPentest(), collection, pipeline, multi)
        
    def findInDb(self, pentest, collection, pipeline=None, multi=True):
        pipeline = {} if pipeline is None else pipeline
        api_url = '{0}find/{1}/{2}'.format(self.api_url_base, pentest, collection)
        data = {"pipeline":(json.dumps(pipeline, cls=JSONEncoder)).replace("'","\""), "many":multi}
        response = requests.post(api_url, headers=self.headers, data=json.dumps(data, cls=JSONEncoder),  proxies=proxies, verify=False)
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None

    def insert(self, collection, data):
        api_url = '{0}{1}/{2}'.format(self.api_url_base, collection, self.getCurrentPentest())
        response = requests.post(api_url, headers=self.headers, data=json.dumps(data, cls=JSONEncoder),  proxies=proxies, verify=False)
        res = json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        return res["res"], res["iid"]
        
    def insertInDb(self, pentest, collection, pipeline=None, parent="", notify=False):
        pipeline = {} if pipeline is None else pipeline
        api_url = '{0}insert/{1}/{2}'.format(self.api_url_base, pentest, collection)
        data = {"pipeline":json.dumps(pipeline, cls=JSONEncoder).replace("'","\""), "parent":parent, "notify":notify}
        response = requests.post(api_url, headers=self.headers, data=json.dumps(data, cls=JSONEncoder))
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None

    def update(self, collection, iid, updatePipeline):
        api_url = '{0}{1}/update/{2}/{3}'.format(self.api_url_base, collection, self.getCurrentPentest(), iid)
        response = requests.put(api_url, headers=self.headers,data=json.dumps(updatePipeline, cls=JSONEncoder))
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None
                
    def updateInDb(self, pentest, collection, pipeline, updatePipeline, many=False, notify=False):
        pipeline = {} if pipeline is None else pipeline
        api_url = '{0}update/{1}/{2}'.format(self.api_url_base, pentest, collection)
        data = {"pipeline":json.dumps(pipeline, cls=JSONEncoder).replace("'","\""), "updatePipeline":json.dumps(updatePipeline, cls=JSONEncoder), "many":many, "notify":notify}
        response = requests.post(api_url, headers=self.headers, data=json.dumps(data, cls=JSONEncoder))
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None

    def delete(self, collection, iid):
        api_url = '{0}{1}/{2}/{3}'.format(self.api_url_base, collection, self.getCurrentPentest(), iid)
        response = requests.delete(api_url, headers=self.headers)
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None
        
    def deleteFromDb(self, pentest, collection, pipeline, many=False, notify=False):
        pipeline = {} if pipeline is None else pipeline
        api_url = '{0}delete/{1}/{2}'.format(self.api_url_base, pentest, collection)
        data = {"pipeline":json.dumps(pipeline, cls=JSONEncoder).replace("'","\""), "many":many, "notify":notify}
        response = requests.post(api_url, headers=self.headers, data=json.dumps(data, cls=JSONEncoder))
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None

    def aggregate(self, collection, pipelines=None):
        pipelines = [] if pipelines is None else pipelines
        api_url = '{0}aggregate/{1}/{2}'.format(self.api_url_base, self.getCurrentPentest(), collection)
        data = pipelines
        response = requests.post(api_url, headers=self.headers, data=json.dumps(data, cls=JSONEncoder))
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None

    def count(self, collection, pipeline=None):
        pipeline = {} if pipeline is None else pipeline
        api_url = '{0}count/{1}/{2}'.format(self.api_url_base, self.getCurrentPentest(), collection)
        data = {"pipeline":json.dumps(pipeline, cls=JSONEncoder).replace("'","\"")}
        response = requests.post(api_url, headers=self.headers, data=json.dumps(data, cls=JSONEncoder))
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return 0

    def getWorkers(self, pipeline=None):
        pipeline = {} if pipeline is None else pipeline
        api_url = '{0}workers'.format(self.api_url_base)
        data = {"pipeline":json.dumps(pipeline, cls=JSONEncoder).replace("'","\"")}
        response = requests.get(api_url, headers=self.headers, params=data)
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        elif response.status_code == 204:
            return []
    
    def getWorker(self, pipeline=None):
        res = self.getWorkers(pipeline)
        if res is not None:
            if len(res) == 1:
                return res[0]
        return None

    def getSettings(self, pipeline=None):
        if pipeline is None:
            api_url = '{0}settings'.format(self.api_url_base)
            params={}
        else:
            api_url = '{0}settings/search'.format(self.api_url_base, pipeline)
            params = {"pipeline":json.dumps(pipeline, cls=JSONEncoder).replace("'","\"")}
        response = requests.get(api_url, headers=self.headers, params=params)
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        elif response.status_code == 404:
            return []
        else:
            return None

    def createSetting(self, key, value):
        api_url = '{0}settings'.format(self.api_url_base)
        data = {"key":key, "value":value}
        response = requests.post(api_url, headers=self.headers, data=json.dumps(data, cls=JSONEncoder))
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None
    
    def updateSetting(self, key, value):
        api_url = '{0}settings'.format(self.api_url_base)
        data = {"key":key, "value":value}
        response = requests.put(api_url, headers=self.headers, data=json.dumps(data, cls=JSONEncoder))
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None

    def sendStopTask(self, toolModelData):
        return False

    def sendLaunchTask(self, toolModel, parser="", checks=True, worker=""):
        pass

    def addCustomTool(self, port_iid, tool_name):
        api_url = '{0}ports/{1}/{2}/addCustomTool/'.format(self.api_url_base, self.getCurrentPentest(), port_iid)
        response = requests.put(api_url, headers=self.headers, data=tool_name)
        if response.status_code == 200:
            return json.loads(response.content.decode('utf-8'), cls=JSONDecoder)
        else:
            return None