"""Handle mongo database connection and add shortcut functions to common stuff."""
import os
import ssl
import datetime
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError, OperationFailure
import pollenisator.core.Components.Utils as Utils
import sys
import json
from pollenisator.core.Components.logger_config import logger
from bson import ObjectId


class MongoCalendar:
    # pylint: disable=unsubscriptable-object
    """
    Centralize all direct contacts with the database.
    """
    __instances = {}

    @staticmethod
    def getInstance():
        """ Singleton Static access method.
        """
        pid = os.getpid()  # HACK : One mongo per process.
        instance = MongoCalendar.__instances.get(pid, None)
        if instance is None:
            MongoCalendar()
        return MongoCalendar.__instances[pid]

    def __init__(self):
        """ DO NOT USE THIS CONSTRUCTOR IT IS A
        Virtually private constructor.  Use MongoCalendar.getInstance()
        Args:
            client: a MongoClient instance or None
            host: the host where the database is running
            user: a user login to the database
            password: a password corresponding with the user to connect to the database
            ssl: Absolute path to the folder containing client.pem and ca.pem or empty if ssl is disabled
            calendarName: the calendar name the db has connected to. Or None if not connected to any calendar.
            ssldir: The string path to a folder where all the ssl certificates are to be found.
            db: The database to the client last connected.
            forbiddenNames: A list of names forbidden for calendars because they are reserved by mongo, this application. ("admin", "config", "local", "broker_pollenisator", "pollenisator")
        Raises:
            Exception if it is instanciated.
        """
        pid = os.getpid()  # HACK : One mongo per process.
        if MongoCalendar.__instances.get(pid, None) is not None:
            raise Exception("This class is a singleton!")
        else:
            self.client = None
            self.host = ""
            self.password = ""
            self.user = ""
            self.ssl = ""
            self.port = ""
            self.calendarName = None
            self.ssldir = ""
            self.db = None
            self.forbiddenNames = ["admin", "config", "local",
                                   "broker_pollenisator", "pollenisator"]
            MongoCalendar.__instances[pid] = self

    def reinitConnection(self):
        """Reset client connection"""
        self.client = None

    def getWorkers(self, pipeline=None):
        """Return workers documents from database
        Returns:
            Mongo result of workers. Cursor of dictionnary."""
        pipeline = {} if pipeline is None else pipeline
        return self.findInDb("pollenisator", "workers", pipeline)

    def getWorker(self, name):
        """Return workers documents from database
        Returns:
            Mongo result of workers. Cursor of dictionnary."""
        return self.findInDb("pollenisator", "workers", {"name":name}, False)

    def setWorkerInclusion(self, name, db, setInclusion):
        """Set the inclusion status of a worker in a pentest.
    
        Args:
            name (str): The name of the worker.
            db (str): The ID of the pentest.
            setInclusion (bool): A flag indicating whether the worker should be included in the pentest (True) or excluded (False).
    
        Returns:
            bool: Always returns True.
        """
        if setInclusion:
            self.updateInDb("pollenisator", "workers", {"name": name}, {
                            "": {"pentest": db}}, False, True)
        else:
            self.updateInDb("pollenisator", "workers", {"name": name}, {
                            "": {"pentest": ""}}, False, True)
        return True
    

    def deleteWorker(self, worker_hostname):
        """Remove given worker.
        Args:
            worker_hostname: the worker name to update."""
        res = self.deleteFromDb("pollenisator", "workers", {
            "name": worker_hostname}, False, True)
        
        return res


    def updateWorkerLastHeartbeat(self, worker_hostname):
        """Update a worker last heart beat sent
        Args:
            worker_hostname: the worker shortname to update.
        """
        return self.updateInDb("pollenisator", "workers", {"name": worker_hostname}, {
                        "$set": {"last_heartbeat": datetime.datetime.now()}})


    def connect(self, config=None, timeoutInMS=500):
        """
        Connect the mongo client to the database using the login provided and ssl certificates if ssl is activated.
        Args:
            config: A dictionnary with server.cfg config values (host, mongo_port, password, user, ssl).
                    Default to None. If None, the server.cfg file will be read.
            timeoutInMs: milliseconds to wait before timeout. Default to 500ms.
        Raises:
            ServerSelectionTimeoutError: if unable to connect to the mongo database
            OperationFailure: if unable to authenticate using user/password.
        Returns:
            None if not connected
            False if connection failed
            True if connected succeeded
        """
        if self.client is not None:
            return
        cfg = config if config is not None else Utils.loadServerConfig()
        try:
            self.host = str(cfg["host"])
            self.port = str(cfg.get("mongo_port", 27017))
            self.password = str(cfg["password"])
            self.user = str(cfg["user"])
            self.ssl = str(cfg["ssl"])

            connectionString = ""
            if self.user != "":
                connectionString = self.user+':'+self.password+'@'
            self.calendarName = None
            try:
                if cfg["ssl"].strip() != "":

                    self.ssldir = cfg["ssl"].strip()
                    self.client = MongoClient('mongodb://'+connectionString+self.host+":"+self.port, ssl=True, ssl_certfile=os.path.join(
                        self.ssldir, "client.pem"), ssl_cert_reqs=ssl.CERT_REQUIRED, ssl_ca_certs=os.path.join(self.ssldir, "ca.pem"), serverSelectionTimeoutMS=timeoutInMS, socketTimeoutMS=2000, connectTimeoutMS=2000)
                else:
                    self.client = MongoClient(
                        'mongodb://'+connectionString+self.host+":"+self.port, serverSelectionTimeoutMS=timeoutInMS)
                server_info = self.client.server_info()
                return True and self.client is not None and server_info is not None
            except ServerSelectionTimeoutError as e:  # Unable to connect
                print(f"Unable to connect to the database:\nPlease check the mongo db is up and reachable and your configuration file is correct: \n{os.path.normpath(Utils.getServerConfigFolder())}/server.cfg")
                print(e)
                sys.exit(0)
            except OperationFailure as e:  #  Authentication failed
                raise e
        except KeyError as e:
            raise e
        return False

    def isUserConnected(self):
        """Return True if the user is able to list databases. False otherwise.
        Returns: bool"""
        return self.listCalendars() is not None

    def connectToDb(self, calendarName):
        """
        Connect to the pentest database given by calendarName (pentestName).

        Args:
            calendarName: the pentest name to which you want to connect
        """
        try:
            if self.client is None:
                self.connect()
                if self.client is None:
                    raise IOError()
            self.calendarName = calendarName
            if calendarName is not None:
                self.db = self.client[calendarName]
                
        except IOError as e:
            print("Failed to connect." + str(e))
            print("Please verify that the mongod service is running on host " +
                  self.host + " and has a user mongAdmin with the correct password.")
            self.client = None

    def removeWorker(self, worker_name):
        """Remove the given worker shortname from database.
        Args:
            worker_name: the worker shortname to be deleted from database."""
        
        self.deleteFromDb("pollenisator", "workers", {
            "name": worker_name}, False, True)

    def registerWorker(self, worker_name, binaries):
        """Register a worker in the database.
    
        Args:
            worker_name (str): The name of the worker.
            binaries (list): A list of strings representing the known commands of the worker.
    
        Returns:
            bool: True if the worker was successfully registered, False otherwise.
        """
        from pollenisator.server.modules.Worker.worker import doSetInclusion
        try:
            if self.client is None:
                self.connect()
                if self.client is None:
                    raise IOError("Failed to register Worker")
            res = self.findInDb("pollenisator", "workers", {"name": worker_name}, False)
            if res is None:
                self.insertInDb("pollenisator", "workers", {"name": worker_name, "pentest": "", "known_commands":binaries}, '', True)
            else:
                self.updateInDb("pollenisator", "workers", {"name": worker_name},
                    {"":{"last_heartbeat":datetime.datetime.now(), "known_commands":binaries,  "pentest":""}}, notify=True)
                doSetInclusion(worker_name,  res["pentest"], True)
            logger.info("Registered worker "+str(worker_name))
            return True
        except IOError as e:
            print("Failed to connect." + str(e))
            print("Please verify that the mongod service is running on host " +
                  self.host + " and has a user mongAdmin with the correct password.")
            self.client = None
            return False
    

    def update(self, collection, pipeline, updatePipeline, many=False, notify=True, upsert=False):
        """
        Wrapper for the pymongo update and update_many functions. Then notify observers.

        Args:
            collection: the collection that holds the document to update
            pipeline: a first "match" pipeline mongo to select which document to update
            updatePipeline: a second "action" pipeline mongo to apply changes to the selected document(s)
            many: a boolean defining if eventually many documents can be modified at once. (If False, only zero or one document will be updated.). Default to False
            notify: a boolean asking for all client to be notified of this update. Default to True.
        Returns:
            Return the pymongo result of the update or update_many function.
        """
        return self._update(self.calendarName, collection, pipeline, updatePipeline, many=many, notify=notify, upsert=upsert)

    def updateInDb(self, db, collection, pipeline, updatePipeline, many=False, notify=True, upsert=False):
        """
        update something in the database.
        Args:
            db: the database name where the object to update is
            collection: the collection that holds the document to update
            pipeline: a first "match" pipeline mongo to select which document to update
            updatePipeline: a second "action" pipeline mongo to apply changes to the selected document(s)
            many: a boolean defining if eventually many documents can be modified at once. (If False, only zero or one document will be updated.). Default to False
            notify: a boolean asking for all client to be notified of this update. Default to False.
        Returns:
            Return the pymongo result of the find command for the command collection
        """
        self.connect()
        return self._update(db, collection, pipeline, updatePipeline, many=many, notify=notify, upsert=upsert)

    def _update(self, dbName, collection, pipeline, updatePipeline, many=False, notify=True, upsert=False):
        """
        Wrapper for the pymongo update and update_many functions. Then notify observers  if notify is true.

        Args:
            dbName: the database name to use
            collection: the collection that holds the document to update
            pipeline: a first "match" pipeline mongo to select which document to update
            updatePipeline: a second "action" pipeline mongo to apply changes to the selected document(s)
            many: a boolean defining if eventually many documents can be modified at once. (If False, only zero or one document will be updated.). Default to False
            notify: a boolean asking for all client to be notified of this update. Default to True.
        Returns:
            Return the pymongo result of the update or update_many function.
        """
        self.connect()
        db = self.client[dbName]
        if many:
            res = db[collection].update_many(
                pipeline, updatePipeline)
            elems = db[collection].find(pipeline)
            if notify:
                for elem in elems:
                    self.notify(dbName, collection, elem["_id"], "update")
        else:
            res = db[collection].update_one(pipeline, updatePipeline, upsert=upsert)
            if upsert and res.upserted_id is not None:
                self.notify(dbName, collection, res.upserted_id, "insert")
            else:
                elem = db[collection].find_one(pipeline)
                if elem is not None:
                    if notify:
                        self.notify(dbName, collection, elem["_id"], "update")
        return res

    def insert(self, collection, values, parent='', notify=True):
        """
        Wrapper for the pymongo insert_one. Then notify observers.

        Args:
            collection: the collection that will hold the document to insert
            values: the document to insert into the given collection
            parent: not used, default to ''. Was used to give info about parent node

        Returns:
            Return the pymongo result of the insert_one function.
        """
        if values.get("parent", None) is None:
            values["parent"] = parent
        ret = self._insert(self.calendarName, collection, values, notify, parent)
        return ret

    def insertInDb(self, db, collection, values, _parent='', notify=True):
        """
        insert something in the database after ensuring connection.
        Args:
            db: the database name to use
            collection: the collection that holds the document to insert
            values: the document to insert into the given collection
            parent: not used, default to ''. Was used to give info about parent node
            notify: a boolean asking for all client to be notified of this update. Default to False.
        Returns:
            Return the pymongo result of the find command for the command collection
        """
        self.connect()
        return self._insert(db, collection, values, notify)

    def _insert(self, dbName, collection, values, notify=True, parentId=''):
        """
        Perform insertion in the database".
        Args:
            dbName: the database name object to use
            collection: the collection that holds the document to insert
            values: the document to insert into the given collection
            notify: a boolean asking for all client to be notified of this update. Default to True.
            parentId: not used, default to ''. Was used to give info about parent node

        Returns:
            Return the pymongo result of the find command for the command collection
        """
        self.connect()
        db = self.client[dbName]
        res = db[collection].insert_one(values)
        if notify:
            self.notify(dbName, collection,
                        res.inserted_id, "insert", parentId)
        return res

    def find(self, collection, pipeline=None, multi=True):
        """
        Wrapper for the pymongo find and find_one.

        Args:
            collection: the collection to search for
            pipeline: the document caracteristics to search for, default to None which means no filtering.
            multi: a boolean defining if eventually many documents can be found at once. (If False, only zero or one document will be found). Default to True.

        Returns:
            Return the pymongo result of the find or find_one function.
        """
        if pipeline is None:
            pipeline = {}
        return self._find(self.db, collection, pipeline, multi)

    def countInDb(self, db, collection, pipeline=None):
        """Count the number of documents in a collection that match a pipeline.
    
        Args:
            db (str): The name of the database.
            collection (str): The name of the collection.
            pipeline (dict, optional): A pipeline specifying the filters to apply to the collection. Defaults to an empty dictionary.
    
        Returns:
            int: The number of documents in the collection that match the pipeline.
        """
        if pipeline is None:
            pipeline = {}
        self.connect()
        return self.client[db][collection].count_documents(pipeline)
    

    def findInDb(self, db, collection, pipeline=None, multi=True, skip=None, limit=None):
        """
        find something in the database.
        Args:
            collection: the collection to search for
            pipeline: the document caracteristics to search for, default to None which means no filtering.
            multi: a boolean defining if eventually many documents can be found at once. (If False, only zero or one document will be found). Default to True.
            skip: skip a number of document in db
            limit: limit the number of document returned
        Returns:
            Return the pymongo result of the find command for the command collection
        """
        if pipeline is None:
            pipeline = {}
        self.connect()
        dbMongo = self.client[db]
        return self._find(dbMongo, collection, pipeline, multi, skip, limit)

    def fetchNotifications(self, pentest, fromTime):
        """Fetch notifications from a specific time for a specific pentest.
    
        Args:
            pentest (str): The ID of the pentest.
            fromTime (str): A string representing the start time for the notifications, in the format "YYYY-MM-DD HH:MM:SS.ffffff".
    
        Returns:
            list: A list of dictionaries representing the notifications.
        """
        date = datetime.datetime.strptime(fromTime, "%Y-%m-%d %H:%M:%S.%f")
        res = self.findInDb("pollenisator", "notifications", {"":[{"db":str(pentest)}, {"db":"pollenisator"}], "time":{"":date}}, True)
        return res
    

    def _find(self, db, collection, pipeline=None, multi=True, skip=None, limit=None):
        """
        Wrapper for the pymongo find and find_one.

        Args:
            db: the database name to search in
            collection: the collection to search in
            pipeline: the document caracteristics to search for, default to None which means no filtering.
            multi: a boolean defining if eventually many documents can be found at once. (If False, only zero or one document will be found). Default to True.
            skip: skip a number of document in db
            limit: limit the number of document returned
        Returns:
            Return the pymongo result of the find or find_one function.
        """
        if pipeline is None:
            pipeline = {}
        self.connect()
        try:
            if multi:
                res = db[collection].find(pipeline)
                if isinstance(skip, int):
                    res.skip(skip)
                if isinstance(limit, int):
                    res.limit(limit)
            else:
                res = db[collection].find_one(pipeline)
        except TypeError as e:
            logger.error("ERROR TypeError : "+str(e))
            return None
        return res

    def aggregate(self, collection, pipelines=None):
        """
        Wrapper for the pymongo aggregate.

        Args:
            collection: the collection to aggregate.
            pipelines: the mongo pipeline for aggregation. Default to None which means empty list pipeline

        Returns:
            Return the pymongo result of the aggregate function
        """
        if pipelines is None:
            pipelines = []
        return self._aggregate(self.db, collection, pipelines)

    def aggregateFromDb(self, db, collection, pipelines=None):
        """
        aggregate something in the database.
        Args:
            db: the database name to search in
            collection: the collection to search in
            pipelines: the mongo pipeline for aggregation. Default to None which means empty list pipeline
        Returns:
            Return the pymongo result of the find command for the command collection
        """
        if pipelines is None:
            pipelines = []
        self.connect()
        dbMongo = self.client[db]
        return self._aggregate(dbMongo, collection, pipelines)

    def _aggregate(self, db, collection, pipelines=None):
        """
        Wrapper for the pymongo aggregate.

        Args:
            db: the database to search in as mongo object
            collection: the collection to aggregate as str.
            pipelines: the mongo pipeline for aggregation.  Default to None which means empty list pipeline

        Returns:
            Return the pymongo result of the aggregate function
        """
        if pipelines is None:
            pipelines = []
        self.connect()
        return db[collection].aggregate(pipelines)

    def delete(self, collection, pipeline, many=False):
        """
        Wrapper for the pymongo delete_one or delete_many. Then notify observers.

        Args:
            collection: the collection that holds the document to delete
            pipeline: the document caracteristics to search for deletion.
            many: a boolean defining if eventually many documents can be deleted at once. (If False, only zero or one document will be deleted.). Default to False

        Returns:
            Return the pymongo result of the delete_one or delete_many function.
        """
        return self._delete(self.calendarName, collection, pipeline, many, True)

    def deleteFromDb(self, db, collection, pipeline, many=False, notify=True):
        """
        aggregate something in the database.
        Args:
            db: the target database name 
            collection: the collection that holds the document to delete
            pipeline: the document caracteristics to search for deletion.
            many: a boolean defining if eventually many documents can be deleted at once. (If False, only zero or one document will be deleted.). Default to False
            notify: a boolean asking for all client to be notified of this update. Default to False.
        Returns:
            Return the pymongo result of the find command for the command collection
        """
        self.connect()
        return self._delete(db, collection, pipeline, many, notify)

    def _delete(self, dbName, collection, pipeline, many=False, notify=True):
        """
        Wrapper for the pymongo delete_one or delete_many. Then notify observers.

        Args:
            dbName: the database to search in
            collection: the collection that holds the document to delete
            pipeline: the document caracteristics to search for deletion.
            many: a boolean defining if eventually many documents can be deleted at once. (If False, only zero or one document will be deleted.). Default to False
            notify: a boolean asking for all client to be notified of this update. Default to True.
        Returns:
            Return the pymongo result of the delete_one or delete_many function.
        """
        self.connect()
        db = self.client[dbName]
        res = None
        if many:
            elems = db[collection].find(pipeline)
            if notify:
                for elem in elems:
                    self.notify(dbName, collection, elem["_id"], "delete")
            res = db[collection].delete_many(pipeline)
        else:
            elem = db[collection].find_one(pipeline)
            if elem is not None:
                if notify:
                    self.notify(dbName, collection, elem["_id"], "delete")
                res = db[collection].delete_one(pipeline)
        return res

    def listCalendars(self, username=None):
        """Return the list of pollenisator databases.
        Raises:
            Raise Exception if client is not connected to database
        Returns:
            None if the server connection is not established. 
            A list of object with pollenisator databases {"nom":"string","owner":"string", "creation_date":"datetime object"}.
        """
        ret = []
        try:
            if self.client is None:
                self.connect()
                if self.client is None:
                    raise Exception()
            calendars = self.findInDb("pollenisator", "calendars")
            try:
                for calendar in calendars:
                    if username is not None:
                        res = self.findInDb(calendar["nom"], "settings", {"key":"pentesters", "value":username}, False)
                        if res is not None or username == calendar.get("owner"):
                            ret.append(calendar)
                    else:
                        ret.append(calendar)
            except OperationFailure:
                print("The connected user has no rights")
                return None
        except ServerSelectionTimeoutError as e:
            print("Failed to connect." + str(e))
            print("Please verify that the mongod service is running on host " +
                  self.host + " and has a user mongAdmin with the correct password.")
            self.client = None
            return None
        return ret

    def listCalendarNames(self, username=None):
        """Return the list of pollenisator databases.
        Raises:
            Raise Exception if client is not connected to database
        Returns:
            None if the server connection is not established. A list of string with pollenisator databases.
        """
        cals = self.listCalendars(username)
        if cals is None:
            return None
        ret = []
        for cal in cals:
            ret.append(cal["nom"])
        return ret

    def hasACalendarOpen(self):
        """
        Return wether or not a calendar is open.

        Returns:
            Return True if a calendar is open, False otherwise.
        """
        return self.calendarName is not None

    def doDeleteCalendar(self, calendarName):
        """
        Remove the given calendar name from the database.

        Args:
            calendarName: the calendar name to delete.
        """
        result = self.deleteFromDb(
            "pollenisator", "calendars", {"nom": calendarName})
        if result is not None:
            if result.deleted_count == 1:
                self.client.drop_database(calendarName)
                return True

        return False

    def validateCalendarName(self, calendarName):
        """Check the database name to see if it usable.
        Checks mongo and pollenisator name overlapping.
        Check space and dot in name.
        Check existing pollenisator pentest database names.
        Returns: a boolean"""
        # check for forbidden names
        if calendarName.strip().lower() in self.forbiddenNames:
            msg = "This name is forbidden."
            return False, msg
        elif "." in calendarName.strip():
            msg = "The name cannot contain a dot (.)."
            return False, msg
        elif " " in calendarName.strip():
            msg = "The name cannot contain a space."
            return False, msg
        calendars = self.listCalendarNames()
        if calendars is None:
            return False, "API has trouble connecting to db. Check api server config."
        calendars = [x.lower() for x in calendars]
        if calendarName.strip().lower() in calendars:
            msg = "A database with the same name already exists."
            return False, msg
        return True, ""

    def registerCalendar(self, owner, saveAsName, askDeleteIfExists=True, autoconnect=True):
        """
        Register a new calendar into database.

        Args:
            owner: the owner's username
            saveAsName: the calendar name to register
            askDeleteIfExists: boolean to ask the user for a deletion in case of an already existing calendar with the same name.
                                If false, and the case appends, calendar will not be registered. Default is True.
            autoconnect: boolean indicating if the database should connect to the calendar after it is registered. Default to True.

        Returns:
            Returns True if calendar was successfully registered, False otherwise.
        """
        oldConnection = self.calendarName
        authorized, msg = self.validateCalendarName(saveAsName.strip().lower())
        # check for forbidden names
        if not authorized:
            logger.warn("LOG : add database attempt failed:"+str(msg))
            return False, msg
        # check if already exists
        self.connectToDb("pollenisator")
        if self.db.calendars.find_one({"nom": saveAsName.strip()}) is not None and askDeleteIfExists:
            msg = "The database has not been overwritten choose a different name to save it."
            return False, msg
        # insert in database  calendars
        self.connectToDb("pollenisator")
        self.db.calendars.insert_one({"nom": saveAsName.strip(), "owner":owner, "creation_date": datetime.datetime.now()})
        self.connectToDb(saveAsName.strip())
        if autoconnect:
            self.connectToDb(saveAsName.strip())
        else:
            self.connectToDb(oldConnection)
        return True, "Success"

    def getPentestUsers(self, pentest):
        pentesters = self.findInDb(pentest, "settings", {"key":"pentesters"}, False)
        if pentesters is None:
            return []
        return pentesters["value"]

    def getPentestOwner(self, pentest):
        pentest_data = self.findInDb("pollenisator", "calendars", {"nom":pentest}, False)
        if pentest_data is None:
            return "admin"
        return pentest_data.get("owner", "admin")

    def getUserRecordFromUsername(self, username):
        ret = self.findInDb("pollenisator", "users", {"username": username}, False)
        if isinstance(ret, dict):
            if "hash" in ret:
                del ret["hash"]
        return ret

    def copyDb(self, fromCopyName, toCopyName):
        """
        Copy a database.

        Args:
            toCopyName: the output calendar will have this name. If default empty string is given, a user window prompt will be used.
            fromCopyName: the calendar name to be copied. If default empty string is given, the opened calendar will be used.
        """
        if fromCopyName == "":
            return "database to copy : empty name", 400
        if toCopyName == "":
            return "database destination name is empty", 400
        if fromCopyName not in self.listCalendarNames():
            return "database to copy : not found", 404
        
        major_version = ".".join(self.client.server_info()["version"].split(".")[:2])
        if float(major_version) < 4.2:
            succeed, msg = self.registerCalendar(self.getPentestOwner(fromCopyName),
                toCopyName, True, True)
            if succeed:
                self.client.admin.command('copydb',
                                          fromdb=fromCopyName,
                                          todb=toCopyName)
            else:
                return msg, 403
            return "Success", 200
        else:
            outpath = self.dumpDb(fromCopyName)
            return self.importDatabase(self.getPentestOwner(fromCopyName), outpath, nsFrom=fromCopyName, nsTo=toCopyName)

    def dumpDb(self, dbName, collection=""):
        """
        Export a database dump into the exports/ folder as a gzip archive.
        It uses the mongodump utily installed with mongodb-org-tools

        Args:
            dbName: the database name to dump
            collection: (Opt.) the collection to dump.
        """
        from pollenisator.core.Components.Utils import execute
        dir_path = os.path.dirname(os.path.realpath(__file__))
        out_path = os.path.join(
            dir_path, "../../exports/", dbName if collection == "" else dbName+"_"+collection)
        connectionString = '' if self.user == '' else "-u "+self.user + \
            " -p "+self.password + " --authenticationDatabase admin "
        cmd = "mongodump "+connectionString+"--host " + \
            self.host+"  --db "+dbName+" --archive="+out_path+".gz --gzip"
        if collection.strip() != "":
            cmd += " -c "+str(collection).strip()
        if self.ssl.strip() != "":
            cmd += " --ssl --sslPEMKeyFile "+self.ssldir+"/client.pem --sslCAFile " + \
                self.ssldir+"/ca.pem --sslAllowInvalidHostnames"
        execute(cmd)
        return out_path+".gz"

    def importDatabase(self, owner, filename, **kwargs):
        """
        Import a database dump into a calendar database.
            It uses the mongorestore utily installed with mongodb-org-tools

        Args:
            filename: the gzip archive name that was exported to be reimported.

        Returns:
            returns True if the import is successfull, False
        """
        from pollenisator.core.Components.Utils import execute
        if kwargs.get("nsTo", None) is not None:
            toDbName = kwargs.get("nsTo")
        else:
            toDbName = os.path.splitext(os.path.basename(filename))[0]
        success, msg = self.registerCalendar(owner, toDbName, True, False)
        if success:
            connectionString = '' if self.user == '' else "-u "+self.user + \
                " -p "+self.password + " --authenticationDatabase admin "
            cmd = "mongorestore "+connectionString+"--host " + \
                self.host+" --archive="+filename+" --gzip"
            if self.ssl.strip() != "":
                cmd += " --ssl --sslPEMKeyFile "+self.ssldir+"/client.pem --sslCAFile " + \
                    self.ssldir+"/ca.pem --sslAllowInvalidHostnames"
            if kwargs.get("nsFrom", None) is not None and kwargs.get("nsTo", None) is not None:
                cmd += " --nsFrom='"+kwargs.get("nsFrom")+".*' --nsTo='"+toDbName+".*'"
            execute(cmd, None, True)
        return msg, 200 if success else 403


    def getRegisteredTags(self):
        tags = self.find("settings", {"key":"tags"}, False)
        if tags is None:
            return []
        pentest_tags = list(tags.keys())
        global_tags = list(self.getGlobalTags().keys())
        return global_tags+pentest_tags

    def getGlobalTags(self):
        mongoInstance = MongoCalendar.getInstance()
        tags = mongoInstance.findInDb("pollenisator", "settings", {"key": "tags"}, False)
        if tags is not None:
            if isinstance(tags["value"], dict):
                return tags["value"]
            elif isinstance(tags["value"], str):
                try:
                    return json.loads(tags["value"])
                except:
                    pass
        return {"todo":"orange", "unscanned":"yellow", "pwned":"red", "Interesting":"dark green", "Uninteresting":"sky blue", "neutral":"white"}
        
    def getTagsGroups(self):
        """Returns groups of tags that may not be applied at the same time
        Returns:
            List of list of strings
        """
        tags = self.getGlobalTags()
        return [tags, ["hidden"]]


    def doRegisterTag(self, pentest, name, color="white"):
        if name in self.getRegisteredTags():
            return False
        if pentest == "pollenisator":
            tags = json.loads(self.findInDb("pollenisator", "settings", {"key":"tags"}, False)["value"], cls=Utils.JSONDecoder)
            self.updateInDb("pollenisator", "settings", {"key":"tags"}, {"$set": {"value":json.dumps(tags,  cls=Utils.JSONEncoder)}}, many=False, notify=True)
        else:
            tags = self.findInDb(pentest, "settings", {"key":"tags"}, False)
            if tags is None:
                self.insertInDb(pentest, "settings", {"key":"tags", "value":{name:color}})
            else:
                tags = tags.get("value", {})
                if name not in tags:
                    tags[name] = color
                    self.updateInDb(pentest, "settings", {"key":"tags"}, {"$set": {"value":tags}}, many=False, notify=True)
        return True    

    # def importCommands(self, filename):
    #     """
    #     Import a database dump into a calendar database.
    #         It uses the mongorestore utily installed with mongodb-org-tools

    #     Args:
    #         filename: the gzip archive name that was exported to be reimported.

    #     Returns:
    #         returns True if the import is successfull, False
    #     """
    #     from pollenisator.core.Components.Utils import execute
    #     if not os.path.isfile(filename):
    #         raise IOError("File does not exist")
    #     connectionString = '' if self.user.strip() == '' else "-u "+self.user + \
    #         " -p "+self.password + " --authenticationDatabase admin "
    #     cmd = "mongorestore "+connectionString+"--host " + \
    #         self.host+" --archive="+filename+" --gzip"
    #     if self.ssl.strip() != "":
    #         cmd += " --ssl --sslPEMKeyFile "+self.ssldir+"/client.pem --sslCAFile " + \
    #             self.ssldir+"/ca.pem --sslAllowInvalidHostnames"
        

    #     execute(cmd, None, False)
    #     return True

    def notify(self, db, collection, iid, action, parentId=""):
        """
        Notify all observers of the modified record from database.
        Uses the observer's notify implementation. This implementation must take the same args as this.
        Args:
            collection: the collection where a document has been modified
            iid: the mongo ObjectId of the document that has been modified
            action: the type of modification performed on this document ("insert", "update" or "delete")
            parentId: (not used) default to "", a node parent id as str
        """
        from pollenisator.api import notify_clients
        notify_clients({"iid": iid, "db": db, "collection": collection, "action": action, "parent": parentId, "time":datetime.datetime.now()})
        # self.client["pollenisator"]["notifications"].insert_one(
        #     {"iid": iid, "db": db, "collection": collection, "action": action, "parent": parentId, "time":datetime.datetime.now()})

    def do_upload(self, pentest, attached_iid, filetype, upfile):
        mongoInstance = MongoCalendar.getInstance()
        local_path = os.path.join(Utils.getMainDir(), "files")
        try:
            os.makedirs(local_path)
        except FileExistsError:
            pass
        filepath = os.path.join(local_path, pentest, filetype, attached_iid)
        if filetype == "result":
            res = mongoInstance.findInDb(pentest, "tools", {"_id": ObjectId(attached_iid)}, False)
            if res is None:
                return "The given iid does not match an existing tool", 404, ""
            else:
                if os.path.isdir(filepath):
                    files = os.listdir(filepath)
                    for existing_file in files:
                        os.remove(os.path.join(filepath, files[0]))
        elif filetype == "proof":
            res = mongoInstance.findInDb(pentest, "defects", {"_id": ObjectId(attached_iid)}, False)
            if res is None:
                return "The given iid does not match an existing defect", 404, ""
        else:
            return "Filetype is not proof nor result", 400, ""
        
        try:
            os.makedirs(filepath)
        except FileExistsError:
            pass
        name = upfile.filename.replace("/", "_")
        filepath = os.path.join(filepath, name)
        with open(filepath, "wb") as f:
            f.write(upfile.stream.read())
        upfile.stream.seek(0)
        
        if filetype == "proof":
            mongoInstance.updateInDb(pentest, "defects", {"_id": ObjectId(attached_iid)}, {"$push":{"proofs":name}})
        return name + " was successfully uploaded", 200, filepath
