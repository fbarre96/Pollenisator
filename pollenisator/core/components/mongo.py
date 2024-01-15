"""Handle mongo database connection and add shortcut functions to common stuff."""
import hashlib
import inspect
import os
import ssl
import datetime
from uuid import uuid4, UUID
from pymongo import MongoClient
import pymongo
from pymongo.errors import ServerSelectionTimeoutError, OperationFailure
import pollenisator.core.components.utils as utils
import sys
import json
import redis
from pollenisator.core.components.logger_config import logger
from bson import ObjectId



class DBClient:
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
        instance = DBClient.__instances.get(pid, None)
        if instance is None:
            DBClient()
        return DBClient.__instances[pid]

    def __init__(self):
        """ DO NOT USE THIS CONSTRUCTOR IT IS A
        Virtually private constructor.  Use DBClient.getInstance()
        Args:
            client: a DBClient instance or None
            host: the host where the database is running
            user: a user login to the database
            password: a password corresponding with the user to connect to the database
            ssl: Absolute path to the folder containing client.pem and ca.pem or empty if ssl is disabled
            current_pentest: the pentest  the db has connected to. Or None if not connected to any pentest.
            ssldir: The string path to a folder where all the ssl certificates are to be found.
            db: The database to the client last connected.
            forbiddenNames: A list of names forbidden for pentests because they are reserved by mongo, this application. ("admin", "config", "local", "broker_pollenisator", "pollenisator")
        Raises:
            Exception if it is instanciated.
        """
        pid = os.getpid()  # HACK : One mongo per process.
        self.redis = None
        if DBClient.__instances.get(pid, None) is not None:
            raise Exception("This class is a singleton!")
        else:
            self.client = None
            self.host = ""
            self.password = ""
            self.user = ""
            self.ssl = ""
            self.port = ""
            self.current_pentest = None
            self.ssldir = ""
            self.db = None
            self.cache_collections = ["ports","ips","checkinstances","commands"]
            self.forbiddenNames = ["admin", "config", "local",
                                   "broker_pollenisator", "pollenisator"]
            DBClient.__instances[pid] = self

    
    def reinitConnection(self):
        """Reset client connection"""
        self.client = None

    def bulk_write(self, pentest, collection, update_operations, notify=True):
        """Bulk write data to the database.
        Args:
            data: A list of dictionnary containing the data to write.
        Returns:
            The result of the bulk write.
        """
        self.connect()
        db = self.client[pentest]
        result = db[collection].bulk_write(update_operations)
        if notify:
            self.send_notify(pentest, collection, "update_many", result.upserted_ids)
        return result

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
                            "$set": {"pentest": db}}, False, True)
        else:
            self.updateInDb("pollenisator", "workers", {"name": name}, {
                            "$set": {"pentest": ""}}, False, True)
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

    def connect_cache(self):
        try:
            if self.redis is None:
                redis_port = int(os.environ.get("REDIS_PORT", 6379))
                redis_host = os.environ.get("REDIS_HOST", "127.0.0.1")
                self.redis = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
        except redis.exceptions.ConnectionError as e:
            logger.error("No redis server found, continuing without will slow down the app.")
            self.redis = None


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
        cfg = config if config is not None else utils.loadServerConfig()
        try:
            self.host = os.environ.get("MONGODB_HOST", str(cfg["host"]))
            self.port = os.environ.get("MONGODB_PORT",str(cfg.get("mongo_port", 27017)))
            self.password = os.environ.get("MONGODB_PASSWORD",str(cfg["password"]))
            self.user = os.environ.get("MONGODB_USER",str(cfg["user"]))
            self.ssl = os.environ.get("MONGODB_SSL",str(cfg["ssl"]))

            connectionString = ""
            if self.user != "":
                connectionString = self.user+':'+self.password+'@'
            self.current_pentest = None
            try:
                if cfg["ssl"].strip() != "":

                    self.ssldir = cfg["ssl"].strip()
                    self.client = MongoClient('mongodb://'+connectionString+self.host+":"+self.port, ssl=True, ssl_certfile=os.path.join(
                        self.ssldir, "client.pem"), ssl_cert_reqs=ssl.CERT_REQUIRED, ssl_ca_certs=os.path.join(self.ssldir, "ca.pem"), serverSelectionTimeoutMS=timeoutInMS, socketTimeoutMS=2000, connectTimeoutMS=2000)
                else:
                    self.client = MongoClient(
                        'mongodb://'+connectionString+self.host+":"+self.port, serverSelectionTimeoutMS=timeoutInMS)
                server_info = self.client.server_info()
                self.connect_cache()
                return True and self.client is not None and server_info is not None
            except ServerSelectionTimeoutError as e:  # Unable to connect
                print(f"Unable to connect to the database:\nPlease check the mongo db is up and reachable and your configuration file is correct: \n{os.path.normpath(utils.getServerConfigFolder())}/server.cfg")
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
        return self.listPentests() is not None

    def connectToDb(self, pentest_uuid):
        """
        Connect to the pentest database given by pentest_uuid (pentest_uuid).

        Args:
            pentest_uuid: the pentest uuid to which you want to connect
        """
        try:
            if self.client is None:
                self.connect()
                if self.client is None:
                    raise IOError()
            self.current_pentest = pentest_uuid
            if pentest_uuid is not None:
                self.db = self.client[pentest_uuid]
                
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

    def resetRunningTools(self):
        dbs = self.listPentestUuids()
        for db in dbs:
            self.updateInDb(db, "tools", {"datef": "None", "scanner_ip": {"$ne": "None"}}, {"$set":{"dated":"None", "datef":"None", "scanner_ip":"None"}, "$pull":{"status":"running"}})
            self.updateInDb(db, "tools", {"datef": "None", "dated": {"$ne": "None"}}, {"$set":{"dated":"None", "datef":"None", "scanner_ip":"None"}, "$pull":{"status":"running"}})
    
    def registerWorker(self, worker_name, supported_plugins):
        """Register a worker in the database.
    
        Args:
            worker_name (str): The name of the worker.
            supported_plugins (list): A list of supported_plugins representing the plugins for which the worker should be capable of running.
    
        Returns:
            bool: True if the worker was successfully registered, False otherwise.
        """
        from pollenisator.server.modules.worker.worker import doSetInclusion
        try:
            if self.client is None:
                self.connect()
                if self.client is None:
                    raise IOError("Failed to register Worker")
            res = self.findInDb("pollenisator", "workers", {"name": worker_name}, False)
            if res is None:
                self.insertInDb("pollenisator", "workers", {"name": worker_name, "pentest": "", "supported_plugins":supported_plugins}, '', notify=True)
            else:
                self.updateInDb("pollenisator", "workers", {"name": worker_name},
                    {"$set":{"last_heartbeat":datetime.datetime.now(), "supported_plugins":supported_plugins,  "pentest":""}}, notify=True)
                doSetInclusion(worker_name,  res["pentest"], True)
            logger.info("Registered worker "+str(worker_name))
            return True
        except IOError as e:
            print("Failed to connect." + str(e))
            print("Please verify that the mongod service is running on host " +
                  self.host + " and has a user mongAdmin with the correct password.")
            self.client = None
            return False
        
    def listCollections(self, pentest):
        self.connectToDb(pentest)
        collections = self.db.list_collection_names()
        return collections

    def create_index(self, pentest, collection, index):
        self.connectToDb(pentest)
        self.db[collection].create_index(index)

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
        return self._update(self.current_pentest, collection, pipeline, updatePipeline, many=many, notify=notify, upsert=upsert)

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
                    self.send_notify(dbName, collection, elem["_id"], "update")
        else:
            if collection in self.cache_collections:
                if len(pipeline) == 1 and isinstance(pipeline[list(pipeline.keys())[0]], ObjectId):
                    cache_key = dbName+"."+collection+"."+str(pipeline[list(pipeline.keys())[0]])
                else:
                    cache_key = dbName+"."+collection+"."+hashlib.md5(json.dumps(pipeline, cls=utils.JSONEncoder).encode()).hexdigest()
                if self.redis:
                    try:
                        self.redis.delete(cache_key)
                    except redis.exceptions.ConnectionError as e:
                        logger.warning("Failed to connect to redis")
                        self.redis = None
            res = db[collection].update_one(pipeline, updatePipeline, upsert=upsert)
            if upsert and res.upserted_id is not None:
                self.send_notify(dbName, collection, res.upserted_id, "insert")
            else:
                elem = db[collection].find_one(pipeline)
                if elem is not None:
                    if notify:
                        #logger.info("Sending notify for "+str(elem["_id"])+" on "+str(updatePipeline))
                        self.send_notify(dbName, collection, elem["_id"], "update")
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
        ret = self._insert(self.current_pentest, collection, values, notify, parent)
        return ret

    def insertInDb(self, db, collection, values, _parent='', notify=True, multi=False):
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
        return self._insert(db, collection, values, notify, _parent, multi)

    def _insert(self, dbName, collection, values, notify=True, parentId='', multi=False):
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
        if multi:
            db = self.client[dbName]
            res = db[collection].insert_many(values, ordered=False)
            if notify:
                self.send_notify(dbName, collection,
                        res.inserted_ids, "insert_many", parentId)
        else:
            db = self.client[dbName]
            res = db[collection].insert_one(values)
            if res.inserted_id is not None and collection in self.cache_collections:
                cache_key = dbName+"."+collection+"."+str(res.inserted_id)
                try:
                    if self.redis:
                        self.redis.set(cache_key, json.dumps(values, cls=utils.JSONEncoder), ex=20)
                except redis.exceptions.ConnectionError as e:
                    logger.warning("Failed to connect to redis")
                    self.redis = None
            if res.inserted_id is not None and notify:
                self.send_notify(dbName, collection,
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
    
    def findInDb(self, db, collection, pipeline=None, multi=True, skip=None, limit=None, use_cache=True):
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
        cache_key = None
        if use_cache and collection in self.cache_collections:
            if not multi and len(pipeline) == 1 and isinstance(pipeline[list(pipeline.keys())[0]], ObjectId):
                cache_key = db+"."+collection+"."+str(pipeline[list(pipeline.keys())[0]])
            elif not multi:
                cache_key = db+"."+collection+"."+hashlib.md5(json.dumps(pipeline, cls=utils.JSONEncoder).encode()).hexdigest()
        dbMongo = self.client[db]
        if cache_key:
            if self.redis:
                try:
                    res = self.redis.get(cache_key)
                    if res:
                        res = json.loads(res, cls=utils.JSONDecoder)
                        return res
                except redis.exceptions.ConnectionError:
                    logger.warning("Failed to connect to redis")
                    self.redis = None
        res =  self._find(dbMongo, collection, pipeline, multi, skip, limit)
        if cache_key and res:
            if inspect.isgenerator(res) or isinstance(res, pymongo.cursor.Cursor):
                res = [r for r in res]
            store = json.dumps(res, cls=utils.JSONEncoder)
            try:
                if self.redis:
                    self.redis.set(cache_key, store, ex=30) #set serialized object to redis server.
            except redis.exceptions.ConnectionError as e:
                logger.warning("Failed to connect to redis")
                self.redis = None
        return res

    def fetchNotifications(self, pentest, fromTime):
        """Fetch notifications from a specific time for a specific pentest.
    
        Args:
            pentest (str): The ID of the pentest.
            fromTime (str): A string representing the start time for the notifications, in the format "YYYY-MM-DD HH:MM:SS.ffffff".
    
        Returns:
            list: A list of dictionaries representing the notifications.
        """
        date = datetime.datetime.strptime(fromTime, "%Y-%m-%d %H:%M:%S.%f")
        res = self.findInDb("pollenisator", "notifications", {"$or":[{"db":str(pentest)}, {"db":"pollenisator"}], "time":{"$gt":date}}, True)
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
        return self._delete(self.current_pentest, collection, pipeline, many, True)

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
        iids = self._delete(db, collection, pipeline, many, notify)
        for iid in iids:
            if db != "pollenisator":
                self._delete(db, "tags", {"target_id":ObjectId(iid)}, False, True)
        return len(iids)

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
        iids_deleted = []
        if many:
            elems = db[collection].find(pipeline)
            if notify:
                for elem in elems:
                    iids_deleted.append(elem["_id"])
                    self.send_notify(dbName, collection, elem["_id"], "delete")
            res = db[collection].delete_many(pipeline)
        else:
            elem = db[collection].find_one(pipeline)
            if elem is not None:
                if notify:
                    iids_deleted.append(elem["_id"])
                    self.send_notify(dbName, collection, elem["_id"], "delete")
                res = db[collection].delete_one(pipeline)

        return iids_deleted

    def listPentests(self, username=None):
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
            pentests = self.findInDb("pollenisator", "pentests")
            try:
                for pentest in pentests:
                    if username is not None:
                        res = self.findInDb(pentest["uuid"], "settings", {"key":"pentesters", "value":username}, False)
                        if res is not None or username == pentest.get("owner"):
                            ret.append(pentest)
                    else:
                        ret.append(pentest)
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

    def listPentestNames(self, username=None):
        """Return the list of pollenisator databases.
        Raises:
            Raise Exception if client is not connected to database
        Returns:
            None if the server connection is not established. A list of string with pollenisator databases.
        """
        cals = self.listPentests(username)
        if cals is None:
            return None
        ret = []
        for cal in cals:
            ret.append(cal["nom"])
        return ret
    
    def listPentestUuids(self, username=None):
        """Return the list of pollenisator databases.
        Raises:
            Raise Exception if client is not connected to database
        Returns:
            None if the server connection is not established. A list of string with pollenisator databases.
        """
        cals = self.listPentests(username)
        if cals is None:
            return None
        ret = []
        for cal in cals:
            ret.append(cal["uuid"])
        return ret

    def hasAPentestOpen(self):
        """
        Return wether or not a pentest is open.

        Returns:
            Return True if a pentest is open, False otherwise.
        """
        return self.current_pentest is not None

    def doDeletePentest(self, pentest_uuid):
        """
        Remove the pentest uuid from the database.

        Args:
            pentest_uuid: the pentest uuid to delete.
        """
        result = self.deleteFromDb(
            "pollenisator", "pentests", {"uuid": pentest_uuid})
        if result is not None:
            if result == 1:
                self.client.drop_database(pentest_uuid)
                return True

        return False

    def validatePentestName(self, pentestName):
        """Check the database name to see if it usable.
        Checks mongo and pollenisator name overlapping.
        Check space and dot in name.
        Check existing pollenisator pentest database names.
        Returns: a boolean"""
        # check for forbidden names
        if pentestName.strip() == "":
            return False, "Name cannot be empty."
        if pentestName.strip().lower() in self.forbiddenNames:
            msg = "This name is forbidden."
            return False, msg
        pentests = self.listPentestNames()
        if pentests is None:
            return False, "API has trouble connecting to db. Check api server config."
        pentests = [x.lower() for x in pentests]
        if pentestName.strip().lower() in pentests:
            msg = "A database with the same name already exists."
            return False, msg
        return True, ""
    
    def editPentest(self, pentest, new_pentest_name):
        """
        Edit pentest data

        Args:
            pentest: the pentest
            new_pentest_name:new pentest name
        Returns:
            Returns True if pentest was successfully edited, False otherwise.
        """
        res, msg = self.validatePentestName(new_pentest_name)
        if not res:
            return res, msg
        res = self.updateInDb("pollenisator", "pentests", {"uuid": pentest}, {"$set": {"nom": new_pentest_name}})
        if res.acknowledged:
            return True, ""
        return False, "Failed to edit pentest name."

    def registerPentest(self, owner, saveAsName, askDeleteIfExists=True, autoconnect=True):
        """
        Register a new pentest into database.

        Args:
            owner: the owner's username
            saveAsName: the pentest name to register
            askDeleteIfExists: boolean to ask the user for a deletion in case of an already existing pentest with the same name.
                                If false, and the case appends, pentest will not be registered. Default is True.
            autoconnect: boolean indicating if the database should connect to the pentest after it is registered. Default to True.

        Returns:
            Returns True if pentest was successfully registered, False otherwise.
        """
        
        oldConnection = self.current_pentest
        authorized, msg = self.validatePentestName(saveAsName.strip().lower())
        # check for forbidden names
        if not authorized:
            logger.warn("LOG : add database attempt failed:"+str(msg))
            return False, msg
        # check if already exists
        self.connectToDb("pollenisator")
        uuid = str(uuid4())
        while self.db.pentests.find_one({"uuid": uuid}) is not None:
            uuid = str(uuid4())
        if self.db.pentests.find_one({"nom": saveAsName.strip()}) is not None and askDeleteIfExists:
            msg = "The database has not been overwritten choose a different name to save it."
            return False, msg
        # insert in database  pentests
        self.connectToDb("pollenisator")
        self.db.pentests.insert_one({"uuid":uuid, "nom": saveAsName.strip(), "owner":owner, "creation_date": datetime.datetime.now()})
        self.connectToDb(uuid)
        if autoconnect:
            self.connectToDb(uuid)
        else:
            self.connectToDb(oldConnection)
        return True, str(uuid)

    def getPentestUsers(self, pentest):
        pentesters = self.findInDb(pentest, "settings", {"key":"pentesters"}, False)
        if pentesters is None:
            return []
        return pentesters["value"]

    def getPentestOwner(self, pentest):
        pentest_data = self.findInDb("pollenisator", "pentests", {"uuid":pentest}, False)
        if pentest_data is None:
            return "admin"
        return pentest_data.get("owner", "admin")

    def getUserRecordFromUsername(self, username):
        ret = self.findInDb("pollenisator", "users", {"username": username}, False)
        if isinstance(ret, dict):
            if "hash" in ret:
                del ret["hash"]
        return ret

    def copyDb(self, fromCopy, toCopy, checkPentestName=True):
        """
        Copy a database.

        Args:
            toCopyName: the output pentest will have this name. If default empty string is given, a user window prompt will be used.
            fromCopyName: the pentest name to be copied. If default empty string is given, the opened pentest will be used.
        """
        if fromCopy == "":
            return "database to copy : empty name", 400
        if toCopy == "":
            return "database destination name is empty", 400
        if fromCopy not in self.listPentestUuids() and checkPentestName:
            return "database to copy : not found", 404
        
        major_version = ".".join(self.client.server_info()["version"].split(".")[:2])
        
        if float(major_version) < 4.2:
            succeed, msg = self.registerPentest(self.getPentestOwner(fromCopy),
                    toCopy, True, True)
            if not succeed:
                return msg, 403
            toCopy = msg
            self.client.admin.command('copydb',
                                        fromdb=fromCopy,
                                        todb=toCopy)
            return "Database copied", 200
        else:
            outpath = self.dumpDb(fromCopy)
            return self.importDatabase(self.getPentestOwner(fromCopy), outpath, nsFrom=fromCopy, nsTo=toCopy)

    def dumpDb(self, dbName, collection=""):
        """
        Export a database dump into the exports/ folder as a gzip archive.
        It uses the mongodump utily installed with mongodb-org-tools

        Args:
            dbName: the database name to dump
            collection: (Opt.) the collection to dump.
        """
        from pollenisator.core.components.utils import execute
        if dbName not in self.listPentestUuids():
            raise ValueError("Database not found")
        if dbName.isalnum() == False:
            raise ValueError("Invalid database name")
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
    
    @staticmethod
    def try_uuid(uuid_to_test):
        try:
            uuid_obj = UUID(uuid_to_test, version=4)
        except ValueError:
            return False
        return str(uuid_obj) == uuid_to_test

    def importDatabase(self, owner, filename, **kwargs):
        """
        Import a database dump into a pentest database.
            It uses the mongorestore utily installed with mongodb-org-tools

        Args:
            filename: the gzip archive name that was exported to be reimported.

        Returns:
            returns True if the import is successfull, False
        """
        from pollenisator.core.components.utils import execute
        if kwargs.get("nsTo", None) is not None:
            toDbName = kwargs.get("nsTo")
        else:
            toDbName = os.path.splitext(os.path.basename(filename))[0]
        success, msg = self.registerPentest(owner, toDbName, True, False)
        uuid_name = msg
        if not self.try_uuid(uuid_name):
            return msg, 403
        if uuid_name not in self.listPentestUuids():
            return "Database not found", 404
        if success:
            connectionString = '' if self.user == '' else "-u "+self.user + \
                " -p "+self.password + " --authenticationDatabase admin "
            cmd = "mongorestore "+connectionString+"--host " + \
                self.host+" --archive="+filename+" --gzip"
            if self.ssl.strip() != "":
                cmd += " --ssl --sslPEMKeyFile "+self.ssldir+"/client.pem --sslCAFile " + \
                    self.ssldir+"/ca.pem --sslAllowInvalidHostnames"
            if kwargs.get("nsFrom", None) is not None and kwargs.get("nsTo", None) is not None:
                nsfrom = kwargs.get("nsFrom")
                if self.try_uuid(nsfrom) and nsfrom in self.listPentestUuids():
                    cmd += " --nsFrom='"+nsfrom+".*' --nsTo='"+uuid_name+".*'"
            execute(cmd, None, True)
        return msg, 200 if success else 403
    

    def getRegisteredTags(self, pentest):
        tags = self.findInDb(pentest,"settings", {"key":"tags"}, False)
        if tags is None:
            return []
        tags = tags.get("value", {})
        if isinstance(tags, str):
            tags = json.loads(tags)
        pentest_tags = list(tags.keys())
        global_tags = list(self.getGlobalTags().keys())
        return global_tags+pentest_tags

    def getGlobalTags(self):
        dbclient = DBClient.getInstance()
        tags = dbclient.findInDb("pollenisator", "settings", {"key": "tags"}, False)
        if tags is not None:
            if isinstance(tags["value"], dict):
                return tags["value"]
            elif isinstance(tags["value"], str):
                try:
                    t = json.loads(tags["value"])
                    if isinstance(t, str): 
                        t = json.loads(t)
                    return t
                except:
                    pass
        return {}
        
    def getTagsGroups(self):
        """Returns groups of tags that may not be applied at the same time
        Returns:
            List of list of strings
        """
        tags = self.getGlobalTags()
        return [tags, ["hidden"]]


    def doRegisterTag(self, pentest, tag):
        if tag.name in self.getRegisteredTags(pentest):
            return False
        if pentest == "pollenisator":
            tags = json.loads(self.findInDb("pollenisator", "settings", {"key":"tags"}, False)["value"], cls=utils.JSONDecoder)
            self.updateInDb("pollenisator", "settings", {"key":"tags"}, {"$set": {"value":json.dumps(tags,  cls=utils.JSONEncoder)}}, many=False, notify=True)
        else:
            tags = self.findInDb(pentest, "settings", {"key":"tags"}, False)
            if tags is None:
                self.insertInDb(pentest, "settings", {"key":"tags", "value":{tag.name:{"color":tag.color, "level":tag.level}}})
            else:
                tags = tags.get("value", {})
                if tag.name not in tags:
                    tags[tag.name] = {"color":tag.color, "level":tag.level}
                    self.updateInDb(pentest, "settings", {"key":"tags"}, {"$set": {"value":tags}}, many=False, notify=True)
        return True    


    def send_notify(self, db, collection, iid, action, parentId=""):
        """
        Notify all observers of the modified record from database.
        Uses the observer's notify implementation. This implementation must take the same args as this.
        Args:
            collection: the collection where a document has been modified
            iid: the mongo ObjectId of the document that has been modified
            action: the type of modification performed on this document ("insert", "update" or "delete")
            parentId: (not used) default to "", a node parent id as str
        """
        from pollenisator.app_factory import notify_clients
        notify_clients({"iid": iid, "db": db, "collection": collection, "action": action, "parent": parentId, "time":datetime.datetime.now()})
        
        # self.client["pollenisator"]["notifications"].insert_one(
        #     {"iid": iid, "db": db, "collection": collection, "action": action, "parent": parentId, "time":datetime.datetime.now()})

    def do_upload(self, pentest, attached_iid, filetype, upfile):
        dbclient = DBClient.getInstance()
        local_path = os.path.join(utils.getMainDir(), "files")
        try:
            os.makedirs(local_path)
        except FileExistsError:
            pass
        filepath = os.path.join(local_path, pentest, filetype, attached_iid)
        if filetype == "result":
            res = dbclient.findInDb(pentest, "tools", {"_id": ObjectId(attached_iid)}, False)
            if res is None:
                return "The given iid does not match an existing tool", 404, ""
            else:
                if os.path.isdir(filepath):
                    files = os.listdir(filepath)
                    for existing_file in files:
                        os.remove(os.path.join(filepath, files[0]))
        elif filetype == "proof":
            res = dbclient.findInDb(pentest, "defects", {"_id": ObjectId(attached_iid)}, False)
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
            dbclient.updateInDb(pentest, "defects", {"_id": ObjectId(attached_iid)}, {"$push":{"proofs":name}})
        return name + " was successfully uploaded", 200, filepath
