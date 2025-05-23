"""Handle mongo database connection and add shortcut functions to common stuff."""
import datetime
import hashlib
import inspect
import json
import os
import ssl
import subprocess
import sys
from collections.abc import Iterable
from typing import Any, Dict, List, Literal, Optional, Tuple, Union, cast, overload
from uuid import UUID, uuid4
import bson
from PIL import Image
import pymongo
import redis
from bson import ObjectId
from pymongo import InsertOne, MongoClient, UpdateOne
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

import pollenisator.core.components.utils as utils
from pollenisator.core.components.logger_config import logger
from pollenisator.core.components.tag import Tag


class DBClient:
    # pylint: disable=unsubscriptable-object
    """Handle mongo database connection and add shortcut functions to common stuff.
    Attributes:
        client: a DBClient instance or None
        host: the host where the database is running
        user: a user login to the database
        password: a password corresponding with the user to connect to the database
        ssl: Absolute path to the folder containing client.pem and ca.pem or empty if ssl is disabled
        current_pentest: the pentest  the db has connected to. Or None if not connected to any pentest.
        ssldir: The string path to a folder where all the ssl certificates are to be found.
        db: The database to the client last connected.
        forbiddenNames: A list of names forbidden for pentests because they are reserved by mongo, this application. ("admin", "config", "local", "broker_pollenisator", "pollenisator")
    
    """

    __instances: Dict[int, 'DBClient'] = {}

    @staticmethod
    def getInstance() -> 'DBClient':
        """ Singleton Static access method.
        """
        pid = os.getpid()  # HACK : One mongo per process.
        instance = DBClient.__instances.get(pid, None)
        if instance is None:
            DBClient()
        return DBClient.__instances[pid]

    def __init__(self) -> None:
        """ DO NOT USE THIS CONSTRUCTOR IT IS A
        Virtually private constructor.  Use DBClient.getInstance()
        Raises:
            Exception if it is instanciated.

        """
        pid = os.getpid()  # HACK : One mongo per process.
        self.redis: Union[None, redis.Redis] = None
        if DBClient.__instances.get(pid, None) is not None:
            raise ValueError("This class is a singleton!")
        else:
            self.client: Union[None, MongoClient] = None
            self.host = ""
            self.password = ""
            self.user = ""
            self.ssl = ""
            self.port = ""
            self.current_pentest: Union[str, None] = None
            self.ssldir = ""
            self.db: Union[pymongo.database.Database[Any], None] = None
            self.cache_collections = ["ports","ips","checkinstances","commands"]
            self.forbiddenNames = ["admin", "config", "local",
                                   "broker_pollenisator", "pollenisator"]
            DBClient.__instances[pid] = self


    def reinitConnection(self) -> None:
        """Reset client connection"""
        self.client = None

    def bulk_write(self, pentest: str, collection: str, update_operations: List[Union[InsertOne, UpdateOne]], notify: bool = True) -> Optional[pymongo.results.BulkWriteResult]:
        """
        Bulk write data to the MongoDB database.

        This function connects to the MongoDB database, selects the specified database and collection, 
        and performs the bulk write operation. If the notify parameter is set to True, it sends a 
        notification with the upserted ids.

        Args:
            pentest (str): The name of the database.
            collection (str): The name of the collection.
            update_operations (list[InsertOne | UpdateOne]): A list of InsertOne or UpdateOne instances representing the operations to be performed.
            notify (bool, optional): A flag indicating whether to send a notification after the operation. Defaults to True.
        Raises:
            ValueError: If pentest is None.
            IOError: If the client is unable to connect.
        Returns:
            Optional[results.BulkWriteResult]: The result of the bulk write operation.
            
        """
        self.connect()
        if self.client is None:
            raise IOError("Failed to connect.")
        if pentest is None:
            raise ValueError("Pentest cannot be None")
        db = self.client[pentest]
        if not update_operations:
            return None
        result: pymongo.results.BulkWriteResult = db[collection].bulk_write(update_operations)
        if notify:
            if result.upserted_ids is None:
                upserted_ids = []
            else:
                upserted_ids = [str(x) for x in result.upserted_ids.values()]
            self.send_notify(pentest, collection, upserted_ids, "update_many")
        return result

    def getWorkers(self, pipeline: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Return workers documents from the database.

        This function connects to the MongoDB database, selects the specified database and collection, 
        and performs a find operation with the provided pipeline.

        Args:
            pipeline (Optional[Dict[str, Any]], optional): A dictionary representing the MongoDB pipeline for the find operation. Defaults to None.

        Returns:
            List[Dict[str, Any]]: A list for the resulting workers
        """
        pipeline = {} if pipeline is None else pipeline
        workers = self.findInDb("pollenisator", "workers", pipeline, True)
        if workers is None:
            return []
        return workers

    def getWorker(self, name: str) -> Union[Dict[str, Any], None]:
        """
        Return a worker document from the database.

        This function connects to the MongoDB database, selects the specified database and collection, 
        and performs a find operation with the provided worker name.

        Args:
            name (str): The name of the worker.

        Returns:
            Union[Dict[str, Any], None]: The resulting document or None
        """
        return self.findInDb("pollenisator", "workers", {"name": name}, False)

    def setWorkerInclusion(self, name: str, db: str, setInclusion: bool) -> bool:
        """
        Set the inclusion status of a worker in a pentest.

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


    def deleteWorker(self, worker_hostname: str) -> int:
        """
        Remove a given worker.

        Args:
            worker_hostname (str): The name of the worker to remove.

        Returns:
            int: The number of result deleted by the operation.
        """
        res = self.deleteFromDb("pollenisator", "workers", {"name": worker_hostname}, False, True)
        return res


    def updateWorkerLastHeartbeat(self, worker_hostname: str) -> pymongo.results.UpdateResult:
        """
        Update a worker's last heartbeat timestamp.

        Args:
            worker_hostname (str): The shortname of the worker to update.

        Returns:
            pymongo.results.UpdateResult: The result of the update operation.
        """
        return self.updateInDb("pollenisator", "workers", {"name": worker_hostname}, {
                        "$set": {"last_heartbeat": datetime.datetime.now()}})

    def connect_cache(self) -> None:
        """
        Connect to the Redis cache.

        This function attempts to connect to a Redis server using the host and port specified in the environment variables. Usable environment variables are REDIS_HOST and REDIS_PORT. If the connection fails, it logs an error and continues without the cache, which may slow down the application.
        If the connection fails, it logs an error and continues without the cache, which may slow down the application.
        """
        try:
            if self.redis is None:
                redis_port = int(os.environ.get("REDIS_PORT", 6379))
                redis_host = os.environ.get("REDIS_HOST", "127.0.0.1")
                self.redis = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
        except redis.exceptions.ConnectionError as _e:
            logger.error("No redis server found, continuing without will slow down the app.")
            self.redis = None


    def connect(self, config: Optional[Dict[str, Union[str, int, bool]]] = None, timeoutInMS: int = 500) -> Optional[bool]:
        """
        Connect the mongo client to the database using environment variables (CHECKED FIRST) or the server.cfg file located in $HOME/.config/pollenisator/server.cfg.

        Args:
            config: A dictionary with server.cfg config values (host, mongo_port, password, user, ssl).
                    Default to None. If None, the server.cfg file will be read.
                    If one environment variable is set, it will be used instead of the server.cfg file variable.
            timeoutInMS: milliseconds to wait before timeout. Default to 500ms.

        Raises:
            ServerSelectionTimeoutError: if unable to connect to the mongo database
            OperationFailure: if unable to authenticate using user/password.

        Returns:
            None if already connected
            True if connection succeeded (otherwise an exception is raised).
        """
        if self.client is not None:
            return None
        cfg = config if config is not None else utils.loadServerConfig()
        try:
            self.host = os.environ.get("MONGODB_HOST", str(cfg["host"]))
            self.port = os.environ.get("MONGODB_PORT",str(cfg.get("mongo_port", 27017)))
            self.password = os.environ.get("MONGODB_PASSWORD",str(cfg["password"]))
            self.user = os.environ.get("MONGODB_USER",str(cfg["user"]))
            self.ssl = os.environ.get("MONGODB_SSL",str(cfg["ssl"])).lower()
            if self.ssl != "true":
                self.ssl = ""

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


    def isUserConnected(self) -> bool:
        """
        Check if the user is connected to the database.

        This function checks if the user is connected to the database by attempting to list the pentests.
        If the listPentests function returns None, it means the user is not connected.

        Returns:
            bool: True if the user is connected, False otherwise.
        """
        return self.listPentests() is not None

    def connectToDb(self, pentest_uuid: str) -> None:
        """
        Connect to the pentest database given by pentest_uuid.

        Args:
            pentest_uuid (str): The pentest uuid to which you want to connect.

        Raises:
            IOError: If unable to connect to the database.
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

    def removeWorker(self, worker_name: str) -> None:
        """
        Remove the given worker shortname from database.

        Args:
            worker_name (str): The worker shortname to be deleted from database.
        """
        self.deleteFromDb("pollenisator", "workers", {"name": worker_name}, False, True)

    def resetRunningTools(self) -> None:
        """
        Reset the status of running tools in all pentest databases.

        This function goes through all pentest databases and resets the status of any tools that are currently running.
        The start and finish dates, as well as the scanner IP, are also reset to "None".
        """
        dbs = self.listPentestUuids()
        if dbs is None:
            return None
        for db in dbs:
            self.updateInDb(db, "tools", {"datef": "None", "scanner_ip": {"$ne": "None"}}, {"$set":{"dated":"None", "datef":"None", "scanner_ip":"None"}, "$pull":{"status":"running"}})
            self.updateInDb(db, "tools", {"datef": "None", "dated": {"$ne": "None"}}, {"$set":{"dated":"None", "datef":"None", "scanner_ip":"None"}, "$pull":{"status":"running"}})

    def registerWorker(self, worker_name: str, supported_plugins: List[str]) -> bool:
        """
        Register a worker in the database.

        Args:
            worker_name (str): The name of the worker.
            supported_plugins (List[str]): A list of supported_plugins representing the plugins for which the worker should be capable of running.

        Raises:
            IOError: If unable to connect to the database.

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
            logger.info("Registered worker %s", worker_name)
            return True
        except IOError as e:
            print("Failed to connect." + str(e))
            print("Please verify that the mongod service is running on host " +
                  self.host + " and has a user mongAdmin with the correct password.")
            self.client = None
            return False

    def listCollections(self, pentest: str) -> List[str]:
        """
        List all collections in the specified pentest database.

        Args:
            pentest (str): The name of the pentest database.

        Returns:
            List[str]: A list of collection names in the specified pentest database.
        """
        self.connectToDb(pentest)
        if self.db is None:
            return []
        collections: List[str] = self.db.list_collection_names()
        return collections

    def create_index(self, pentest: str, collection: str, index: List[Tuple[str, int]]) -> None:
        """
        Create an index in the specified collection of the pentest database.

        Args:
            pentest (str): The name of the pentest database.
            collection (str): The name of the collection where the index will be created.
            index List[tuple(str, int)]: The fields used for indexations like [("field1", 1), ("field2", 1]
        """
        self.connectToDb(pentest)
        if self.db is None:
            return None
        self.db[collection].create_index(index)

    def update(self, collection: str, pipeline: Dict[str, Any], updatePipeline: Dict[str, Any], many: bool = False, notify: bool = True, upsert: bool = False) -> pymongo.results.UpdateResult:
        """
        Wrapper for the pymongo update and update_many functions. Then notify observers.

        Args:
            collection (str): The collection that holds the document to update.
            pipeline (Dict[str, Any]): A first "match" pipeline mongo to select which document to update.
            updatePipeline (Dict[str, Any]): A second "action" pipeline mongo to apply changes to the selected document(s).
            many (bool, optional): A boolean defining if eventually many documents can be modified at once. If False, only zero or one document will be updated. Defaults to False.
            notify (bool, optional): A boolean asking for all client to be notified of this update. Defaults to True.
            upsert (bool, optional): A boolean defining if a new document should be created if no document matches the query. Defaults to False.
        Raises:
            ValueError: If no pentest is connected.
        Returns:
            pymongo.results.UpdateResult: Return the pymongo result of the update or update_many function.
        
        """
        if self.current_pentest is None:
            raise ValueError("No pentest connected")
        return self._update(self.current_pentest, collection, pipeline, updatePipeline, many=many, notify=notify, upsert=upsert)

    def updateInDb(self, db: str, collection: str, pipeline: Dict[str, Any], updatePipeline: Dict[str, Any], many: bool = False, notify: bool = True, upsert: bool = False) -> pymongo.results.UpdateResult:
        """
        Update something in the database.

        Args:
            db (str): The database name where the object to update is.
            collection (str): The collection that holds the document to update.
            pipeline (Dict[str, Any]): A first "match" pipeline mongo to select which document to update.
            updatePipeline (Dict[str, Any]): A second "action" pipeline mongo to apply changes to the selected document(s).
            many (bool, optional): A boolean defining if eventually many documents can be modified at once. If False, only zero or one document will be updated. Defaults to False.
            notify (bool, optional): A boolean asking for all client to be notified of this update. Defaults to True.
            upsert (bool, optional): A boolean defining if a new document should be created if no document matches the query. Defaults to False.

        Returns:
           pymongo.results.UpdateResult: Return the pymongo result of the update or update_many function.
        
        """
        self.connect()
        return self._update(db, collection, pipeline, updatePipeline, many=many, notify=notify, upsert=upsert)

    def _update(self, dbName: str, collection: str, pipeline: Dict[str, Any], updatePipeline: Dict[str, Any], many: bool = False, notify: bool = True, upsert: bool = False) -> pymongo.results.UpdateResult:
        """
        Wrapper for the pymongo update and update_many functions. Then notify observers if notify is true.

        Args:
            dbName (str): The database name to use.
            collection (str): The collection that holds the document to update.
            pipeline (Dict[str, Any]): A first "match" pipeline mongo to select which document to update.
            updatePipeline (Dict[str, Any]): A second "action" pipeline mongo to apply changes to the selected document(s).
            many (bool, optional): A boolean defining if eventually many documents can be modified at once. If False, only zero or one document will be updated. Defaults to False.
            notify (bool, optional): A boolean asking for all client to be notified of this update. Defaults to True.
            upsert (bool, optional): A boolean defining if a new document should be created if no document matches the query. Defaults to False.
        Raises:
            ValueError: If no pentest is connected.
        Returns:
            pymongo.results.UpdateResult: Return the pymongo result of the update or update_many function.
        """

        self.connect()
        if self.client is None:
            raise ValueError("No pentest connected")
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
                    except redis.exceptions.ConnectionError as _e:
                        logger.warning("Failed to connect to redis")
                        self.redis = None
            res = db[collection].update_one(pipeline, updatePipeline, upsert=upsert)
            if upsert and res.upserted_id is not None:
                self.send_notify(dbName, collection, res.upserted_id, "insert")
            else:
                elem = db[collection].find_one(pipeline)
                if elem is not None:
                    if notify:
                        self.send_notify(dbName, collection, elem["_id"], "update")
        return res

    def insert(self, collection: str, values: Dict[str, Any], parent: Optional[ObjectId] = None, notify: bool = True) -> Union[pymongo.results.InsertManyResult, pymongo.results.InsertOneResult]:
        """
        Wrapper for the pymongo insert_one. Then notify observers.

        Args:
            collection (str): The collection that will hold the document to insert.
            values (Dict[str, Any]): The document to insert into the given collection.
            parent (str, optional): Not used, default to ''. Was used to give info about parent node.
            notify (bool, optional): A boolean asking for all client to be notified of this insert. Defaults to True.
        Raises:
            ValueError: If no pentest is connected.
        Returns:
            Union(pymongo.results.InsertManyResult, pymongo.results.InsertOneResult): Return the pymongo result of the insert_one function.
        """
        if values.get("parent", None) is None:
            values["parent"] = parent
        if self.current_pentest is None:
            raise ValueError("No pentest connected")
        ret = self._insert(self.current_pentest, collection, values, notify, parent)
        return ret

    def insertManyInDb(self, db: str, collection: str, values: List[Dict[str, Any]], parent: Optional[ObjectId] = None, notify: bool = True) -> pymongo.results.InsertManyResult:
        """
        Insert many documents in the database.

        Args:
            db (str): The name of the database.
            collection (str): The name of the collection.
            values (List[Dict[str, Any]]): The list of documents to insert into the collection.
            parent (ObjectId, optional): the parent id of the documents to insert. Defaults to None.
            notify (bool, optional): A boolean asking for all client to be notified of this insert. Defaults to True.
        
        Returns:
            pymongo.results.InsertManyResult: The result of the insert_many operation.
        """
        self.connect()
        return self._insert(db, collection, values, notify, parent, True)


    def insertInDb(self, db: str, collection: str, values: Dict[str, Any], parent: Optional[ObjectId] = None, notify: bool = True) -> pymongo.results.InsertOneResult:
        """
        Insert something in the database after ensuring connection.

        Args:
            db (str): The database name to use.
            collection (str): The collection that holds the document to insert.
            values (Dict[str, Any]): The document to insert into the given collection.
            parent (ObjectId, optional):
            notify (bool, optional): A boolean asking for all client to be notified of this update. Default to True.

        Returns:
            pymongo.results.InsertOneResult: Return the pymongo result of the insert command for the command collection.
        """
        self.connect()
        return self._insert(db, collection, values, notify, parent, False)

    @overload
    def _insert(self, dbName: str, collection: str, values: Dict[str, Any], notify: bool = True, parentId: Optional[ObjectId] = None, multi: Literal[False] = False) ->  pymongo.results.InsertOneResult:
        ...
    @overload
    def _insert(self, dbName: str, collection: str, values: List[Dict[str, Any]], notify: bool = True, parentId: Optional[ObjectId] = None, multi: Literal[True] = True) ->  pymongo.results.InsertManyResult:
        ...
    def _insert(self, dbName: str, collection: str, values: Union[Dict[str, Any], List[Dict[str, Any]]], notify: bool = True, parentId: Optional[ObjectId] = None, multi: bool = False) -> Union[pymongo.results.InsertOneResult, pymongo.results.InsertManyResult]:
        """
        Perform insertion in the database.

        Args:
            dbName (str): The database name object to use.
            collection (str): The collection that holds the document to insert.
            values (Union[Dict[str, Any], List[Dict[str, Any]]]): The document(s) to insert into the given collection.
            notify (bool, optional): A boolean asking for all client to be notified of this update. Default to True.
            parentId (ObjectId, optional):  default to None
            multi (bool, optional): A boolean defining if multiple documents can be inserted at once. Default to False.

        Returns:
            Union[pymongo.results.InsertOneResult, pymongo.results.InsertManyResult]: Return the pymongo result of the insert command for the command collection.
        """
        self.connect()
        if self.client is None:
            raise ValueError("No pentest connected")
        if multi:
            db = self.client[dbName]
            res_many: pymongo.results.InsertManyResult = db[collection].insert_many(values, ordered=False)
            if notify:
                self.send_notify(dbName, collection,
                        list(map(str, res_many.inserted_ids)), "insert_many", str(parentId))
        else:
            db = self.client[dbName]
            try:
                res_solo: pymongo.results.InsertOneResult = db[collection].insert_one(values)
            except bson.errors.InvalidDocument as e:
                new_values_str = json.dumps(values, cls=utils.JSONEncoder)
                values = json.loads(new_values_str, cls=utils.JSONDecoder)
                res_solo = db[collection].insert_one(values)
            if res_solo.inserted_id is not None and collection in self.cache_collections:
                cache_key = dbName+"."+collection+"."+str(res_solo.inserted_id)
                try:
                    if self.redis:
                        self.redis.set(cache_key, json.dumps(values, cls=utils.JSONEncoder), ex=20)
                except redis.exceptions.ConnectionError as _e:
                    logger.warning("Failed to connect to redis")
                    self.redis = None
            if res_solo.inserted_id is not None and notify:
                self.send_notify(dbName, collection,
                            str(res_solo.inserted_id), "insert", str(parentId))
        return res_many if multi else res_solo

    def find(self, collection: str, pipeline: Optional[Dict[str, Any]] = None, multi: bool = True) -> Union[pymongo.cursor.Cursor, None, List[Dict[str, Any]]]:
        """
        Wrapper for the pymongo find and find_one.

        Args:
            collection (str): The collection to search for.
            pipeline (Optional[Dict[str, Any]], optional): The document characteristics to search for, default to None which means no filtering.
            multi (bool, optional): A boolean defining if eventually many documents can be found at once. If False, only zero or one document will be found. Default to True.

        Returns:
            Union[pymongo.cursor.Cursor, None, List[Dict[str, Any]]]: Return the pymongo result of the find or find_one function.
        """
        if pipeline is None:
            pipeline = {}
        if self.db is None:
            raise ValueError("No pentest connected")
        return self._find(self.db, collection, pipeline, multi)

    def countInDb(self, db: str, collection: str, pipeline: Optional[Dict[str, Any]] = None) -> int:
        """
        Count the number of documents in a collection that match a pipeline.

        Args:
            db (str): The name of the database.
            collection (str): The name of the collection.
            pipeline (Optional[Dict[str, Any]], optional): A pipeline specifying the filters to apply to the collection. Defaults to None which means no filtering.

        Returns:
            int: The number of documents in the collection that match the pipeline.
        """
        if pipeline is None:
            pipeline = {}
        self.connect()
        if self.client is None:
            raise ValueError("No pentest connected")
        if self.client[db] is None:
            raise ValueError("No pentest connected")
        try:
            return self.client[db][collection].count_documents(pipeline)
        except pymongo.errors.OperationFailure as e:
            logger.warning("Failed to count in db")
            raise e
    
    
    @overload
    def findInDb(self, db: str, collection: str, pipeline: Dict[str, Any], multi: Literal[False], skip: Optional[int] = None, limit: Optional[int] = None, use_cache: bool = True) -> Dict[str, Any]:
        ...

    @overload
    def findInDb(self, db: str, collection: str, pipeline: Dict[str, Any], multi: Literal[True] = True , skip: Optional[int] = None, limit: Optional[int] = None, use_cache: bool = True) -> List[Dict[str, Any]]:
        ...
    
    def findInDb(self, db: str, collection: str, pipeline: Dict[str, Any], multi: bool = True, skip: Optional[int] = None, limit: Optional[int] = None, use_cache: bool = True) -> Union[Dict[str, Any], List[Dict[str, Any]], None, pymongo.cursor.Cursor]:
        """
        Find something in the database.

        Args:
            db (str): The database name to use.
            collection (str): The collection to search for.
            pipeline [Dict[str, Any]: The document characteristics to search for, default to None which means no filtering.
            multi (bool, optional): A boolean defining if eventually many documents can be found at once. If False, only zero or one document will be found. Default to True.
            skip (Optional[int], optional): Skip a number of documents in db. Default to None which means no skipping.
            limit (Optional[int], optional): Limit the number of documents returned. Default to None which means no limit.
            use_cache (bool, optional): A boolean defining if the cache should be used. Default to True.

        Returns:
            Union[Dict[str, Any], List[Dict[str, Any]], None, pymongo.cursor.Cursor]: Return the pymongo result of the find command for the command collection.
        """
        if pipeline is None:
            pipeline = {}
        self.connect()
        if self.client is None:
            raise ValueError("No pentest connected")
        cache_key = None
        if use_cache and collection in self.cache_collections:
            if not multi and len(pipeline) == 1 and isinstance(pipeline[list(pipeline.keys())[0]], ObjectId):
                cache_key = db+"."+collection+"."+str(pipeline[list(pipeline.keys())[0]])
            elif not multi:
                cache_key = db+"."+collection+"."+hashlib.md5(json.dumps(pipeline, cls=utils.JSONEncoder).encode()).hexdigest()
        dbMongo: pymongo.database.Database[Any] = self.client[db]
        if cache_key:
            if self.redis:
                try:
                    res_redis: Any = self.redis.get(cache_key)
                    if res_redis:
                        res: Union[Dict[str, Any], List[Dict[str, Any]]] = json.loads(res_redis, cls=utils.JSONDecoder)
                        return res
                except redis.exceptions.ConnectionError:
                    logger.warning("Failed to connect to redis")
                    self.redis = None
        find_res: Union[pymongo.cursor.Cursor, None, List[Dict[str, Any]]] =  self._find(dbMongo, collection, pipeline, multi, skip, limit)
        if cache_key and find_res:
            if inspect.isgenerator(find_res) or isinstance(find_res, pymongo.cursor.Cursor):
                return_value: List[Dict[str, Any]] = [r for r in find_res]
            else:
                return_value = find_res
            store = json.dumps(return_value, cls=utils.JSONEncoder)
            try:
                if self.redis:
                    self.redis.set(cache_key, store, ex=30) #set serialized object to redis server.
            except redis.exceptions.ConnectionError as _e:
                logger.warning("Failed to connect to redis")
                self.redis = None
            return return_value
        return find_res

    def fetchNotifications(self, pentest: str, fromTime: str) -> List[Dict[str, Any]]:
        """
        Fetch notifications from a specific time for a specific pentest.

        Args:
            pentest (str): The ID of the pentest.
            fromTime (str): A string representing the start time for the notifications, in the format "YYYY-MM-DD HH:MM:SS.ffffff".

        Returns:
            List[Dict[str, Any]]: A list of dictionaries representing the notifications.
        """
        date = datetime.datetime.strptime(fromTime, "%Y-%m-%d %H:%M:%S.%f")
        res = self.findInDb("pollenisator", "notifications", {"$or":[{"db":str(pentest)}, {"db":"pollenisator"}], "time":{"$gt":date}}, True)
        return res
    

    def _find(self, db: Any, collection: str, pipeline: Optional[Dict[str, Any]] = None, multi: bool = True, skip: Optional[int] = None, limit: Optional[int] = None) -> Union[pymongo.cursor.Cursor, None, List[Dict[str, Any]]]:
        """
        Wrapper for the pymongo find and find_one.

        Args:
            db (pymongo.database.Database[Any]): The database to search in.
            collection (str): The collection to search in.
            pipeline (Optional[Dict[str, Any]], optional): The document characteristics to search for, default to None which means no filtering.
            multi (bool, optional): A boolean defining if eventually many documents can be found at once. If False, only zero or one document will be found. Default to True.
            skip (Optional[int], optional): Skip a number of documents in db. Default to None which means no skipping.
            limit (Optional[int], optional): Limit the number of documents returned. Default to None which means no limit.

        Returns:
           Union[pymongo.cursor.Cursor, None, List[Dict[str, Any]]]: Return the pymongo result of the find or find_one function.
        """
        if pipeline is None:
            pipeline = {}
        self.connect()
        try:
            if multi:
                res_multi: Union[pymongo.cursor.Cursor, None] = db[collection].find(pipeline)
                if res_multi is None:
                    return []
                if isinstance(skip, int):
                    res_multi.skip(skip)
                if isinstance(limit, int):
                    res_multi.limit(limit)
                return res_multi
            else:
                res_one = db[collection].find_one(pipeline)
                return res_one
        except TypeError as e:
            logger.error("ERROR TypeError : %s", e)
            return None

    def aggregate(self, collection: str, pipelines: Optional[List[Dict[str, Any]]] = None) -> pymongo.command_cursor.CommandCursor:
        """
        Wrapper for the pymongo aggregate.

        Args:
            collection (str): The collection to aggregate.
            pipelines (Optional[List[Dict[str, Any]]], optional): The mongo pipeline for aggregation. Default to None which means empty list pipeline.

        Returns:
            pymongo.command_cursor.CommandCursor: Return the pymongo result of the aggregate function.
        """
        if pipelines is None:
            pipelines = []
        if self.db is None:
            raise ValueError("No pentest connected")
        return self._aggregate(self.db, collection, pipelines)

    def aggregateFromDb(self, db: str, collection: str, pipelines: Optional[List[Dict[str, Any]]] = None) -> pymongo.command_cursor.CommandCursor:
        """
        Aggregate something in the database.

        Args:
            db (str): The database name to search in.
            collection (str): The collection to search in.
            pipelines (Optional[List[Dict[str, Any]]], optional): The mongo pipeline for aggregation. Default to None which means empty list pipeline.

        Returns:
            pymongo.command_cursor.CommandCursor: Return the pymongo result of the aggregate command for the command collection.
        """
        if pipelines is None:
            pipelines = []
        self.connect()
        if self.client is None:
            raise ValueError("No pentest connected")
        dbMongo = self.client[db]
        return self._aggregate(dbMongo, collection, pipelines)

    def _aggregate(self, db: pymongo.database.Database, collection: str, pipelines: Optional[List[Dict[str, Any]]] = None) -> pymongo.command_cursor.CommandCursor:
        """
        Wrapper for the pymongo aggregate.

        Args:
            db (pymongo.database.Database): The database to search in as mongo object.
            collection (str): The collection to aggregate.
            pipelines (Optional[List[Dict[str, Any]]], optional): The mongo pipeline for aggregation. Default to None which means empty list pipeline.

        Returns:
            pymongo.command_cursor.CommandCursor: Return the pymongo result of the aggregate function.
        """
        if pipelines is None:
            pipelines = []
        self.connect()
        return db[collection].aggregate(pipelines)

    def delete(self, collection: str, pipeline: Dict[str, Any], many: bool = False) -> List[ObjectId]:
        """
        Wrapper for the pymongo delete_one or delete_many. Then notify observers.

        Args:
            collection (str): The collection that holds the document to delete.
            pipeline (Dict[str, Any]): The document characteristics to search for deletion.
            many (bool, optional): A boolean defining if eventually many documents can be deleted at once. If False, only zero or one document will be deleted. Default to False.

        Returns:
           List[ObjectId]: Return the deleted object ids.
        """
        if self.current_pentest is None:
            raise ValueError("No pentest connected")
        return self._delete(self.current_pentest, collection, pipeline, many, True)

    def deleteFromDb(self, db: str, collection: str, pipeline: Dict[str, Any], many: bool = False, notify: bool = True) -> int:
        """
        Delete something in the database and optionally notify all clients.

        Args:
            db (str): The target database name.
            collection (str): The collection that holds the document to delete.
            pipeline (Dict[str, Any]): The document characteristics to search for deletion.
            many (bool, optional): A boolean defining if eventually many documents can be deleted at once. If False, only zero or one document will be deleted. Default to False.
            notify (bool, optional): A boolean asking for all client to be notified of this update. Default to True.

        Returns:
            int: The number of documents deleted.
        """
        self.connect()
        iids = self._delete(db, collection, pipeline, many, notify)
        for iid in iids:
            if db != "pollenisator":
                self._delete(db, "tags", {"target_id":ObjectId(iid)}, False, True)
        return len(iids)

    def _delete(self, dbName: str, collection: str, pipeline: Dict[str, Any], many: bool = False, notify: bool = True) -> List[ObjectId]:
        """
        Wrapper for the pymongo delete_one or delete_many. Then notify observers.

        Args:
            dbName (str): The database to search in.
            collection (str): The collection that holds the document to delete.
            pipeline (Dict[str, Any]): The document characteristics to search for deletion.
            many (bool, optional): A boolean defining if eventually many documents can be deleted at once. If False, only zero or one document will be deleted. Default to False.
            notify (bool, optional): A boolean asking for all client to be notified of this update. Default to True.

        Returns:
            List[ObjectId]: List of ObjectIds of the deleted documents.
        """
        self.connect()
        if self.client is None:
            raise ValueError("No pentest connected")
        db = self.client[dbName]
        iids_deleted = []
        if many:
            elems = db[collection].find(pipeline)
            if notify:
                for elem in elems:
                    iids_deleted.append(elem["_id"])
                    self.send_notify(dbName, collection, elem["_id"], "delete")
            db[collection].delete_many(pipeline)
        else:
            elem = db[collection].find_one(pipeline)
            if elem is not None:
                if notify:
                    iids_deleted.append(elem["_id"])
                    self.send_notify(dbName, collection, elem["_id"], "delete")
                db[collection].delete_one(pipeline)

        return iids_deleted

    def listPentests(self, username: Optional[str] = None) -> Optional[List[Dict[str, Union[str, datetime.datetime]]]]:
        """
        Return the list of pollenisator databases.

        Args:
            username (Optional[str], optional): The username to filter the pentests. If None, no filtering is done. Defaults to None.

        Raises:
            Exception: If client is not connected to database.

        Returns:
            Optional[List[Dict[str, Union[str, datatime.datetime]]]]: None if the server connection is not established. 
            A list of objects with pollenisator databases {"nom":"string", "uuid":"string", "owner":"string", "creation_date":"datetime object"}.
        """
        ret = []
        try:
            if self.client is None:
                self.connect()
                if self.client is None:
                    raise ValueError("No pentest connected")
            pentests = self.findInDb("pollenisator", "pentests", {}, True)
            
            try:
                if not isinstance(pentests, Iterable) or pentests is None:
                    return None
                for pentest in pentests: # pylint: disable=not-an-iterable
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

    def listPentestNames(self, username: Optional[str] = None) -> Optional[List[str]]:
        """
        Return the list of pollenisator database names only (not their uuids).

        Args:
            username (Optional[str], optional): The username to filter the pentests. If None, no filtering is done. Defaults to None.

        Raises:
            Exception: If client is not connected to database.

        Returns:
            Optional[List[str]]: None if the server connection is not established. A list of strings with pollenisator database names.
        """
        cals = self.listPentests(username)
        if cals is None:
            return None
        ret: List[str] = []
        for cal in cals:
            ret.append(str(cal["nom"]))
        return ret

    def listPentestUuids(self, username: Optional[str] = None) -> List[str]:
        """
        Return the list of pollenisator database UUIDs.

        Args:
            username (Optional[str], optional): The username to filter the pentests. If None, no filtering is done. Defaults to None.

        Raises:
            Exception: If client is not connected to database.

        Returns:
            Optional[List[str]]: None if the server connection is not established. A list of strings with pollenisator database UUIDs.
        """
        cals = self.listPentests(username)
        if cals is None:
            return []
        ret: List[str] = []
        for cal in cals:
            ret.append(str(cal["uuid"]))
        return ret

    def hasAPentestOpen(self) -> bool:
        """
        Return whether or not a pentest is open.

        Returns:
            bool: True if a pentest is open, False otherwise.
        """
        return self.current_pentest is not None

    def doDeletePentest(self, pentest_uuid: str) -> bool:
        """
        Remove the pentest uuid from the database.

        Args:
            pentest_uuid (str): The pentest uuid to delete.

        Returns:
            bool: True if the pentest was successfully deleted, False otherwise.
        """
        if self.client is None:
            raise ValueError("No pentest connected")
        result = self.deleteFromDb(
            "pollenisator", "pentests", {"uuid": pentest_uuid})
        if result is not None:
            if result == 1:
                self.client.drop_database(pentest_uuid)
                return True
        return False

    def validatePentestName(self, pentestName: str) -> Tuple[bool, str]:
        """
        Check the database name to see if it usable.
        Checks mongo and pollenisator name overlapping.
        Check space and dot in name.
        Check existing pollenisator pentest database names.

        Args:
            pentestName (str): The name of the pentest to validate.

        Returns:
            Tuple[bool, str]: A tuple containing a boolean indicating whether the name is valid or not, and a string message explaining the reason if it's not valid.
        """
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
    
    def editPentest(self, pentest: str, new_pentest_name: str) -> Tuple[bool, str]:
        """
        Edit pentest data.

        Args:
            pentest (str): The current name of the pentest.
            new_pentest_name (str): The new name for the pentest.

        Returns:
            Tuple[bool, str]: A tuple containing a boolean indicating whether the pentest was successfully edited or not, and a string message explaining the reason if it was not successful.
        """
        res, msg = self.validatePentestName(new_pentest_name)
        if not res:
            return res, msg
        res_update: pymongo.results.UpdateResult = self.updateInDb("pollenisator", "pentests", {"uuid": pentest}, {"$set": {"nom": new_pentest_name}})
        if res_update.acknowledged:
            return True, ""
        return False, "Failed to edit pentest name."

    def registerPentest(self, owner: str, saveAsName: str, saveAsUuid:Optional[str] = None, askDeleteIfExists: bool = True, autoconnect: bool = True) -> Tuple[bool, str]:
        """
        Register a new pentest into database.

        Args:
            owner (str): The owner's username.
            saveAsName (str): The pentest name to register.
            saveAsUuid (Optional[str]): The pentest uuid to register.
            askDeleteIfExists (bool, optional): Boolean to ask the user for a deletion in case of an already existing pentest with the same name.
                                                 If false, and the case appends, pentest will not be registered. Default is True.
            autoconnect (bool, optional): Boolean indicating if the database should connect to the pentest after it is registered. Default to True.

        Returns:
            Tuple[bool, str]: Returns a tuple with a boolean indicating if pentest was successfully registered and a string message or the uuid of the pentest.
        """
        self.connect()
        oldConnection = self.current_pentest
        authorized, msg = self.validatePentestName(saveAsName.strip().lower())
        # check for forbidden names
        if not authorized:
            logger.warning("LOG : add database attempt failed: %s", str(msg))
            return False, msg
        # check if already exists
        self.connectToDb("pollenisator")
        if self.db is None:
            raise ValueError("Could not connect to pollenisator database")
        if saveAsUuid is not None:
            uuid = str(saveAsUuid)
            if not self.try_uuid(uuid):
                return False, "Invalid UUID"
                
        else:
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
        elif oldConnection is not None:
            self.connectToDb(oldConnection)
        return True, str(uuid)

    def getPentestUsers(self, pentest: str) -> List[str]:
        """
        Get the users of a specific pentest.

        Args:
            pentest (str): The name of the pentest.

        Returns:
            List[str]: A list of usernames who are users of the specified pentest. If no users are found, an empty list is returned.
        """
        pentesters = self.findInDb(pentest, "settings", {"key":"pentesters"}, False)
        if pentesters is None:
            return []
        value: List[str] = pentesters["value"]
        return value

    def getPentestOwner(self, pentest: str) -> str:
        """
        Get the owner of a specific pentest.

        Args:
            pentest (str): The name of the pentest.

        Returns:
            str: The username of the owner of the specified pentest. If no owner is found, 'admin' is returned.
        """
        pentest_data = self.findInDb("pollenisator", "pentests", {"uuid":pentest}, False)
        if pentest_data is None:
            return "admin"
        return str(pentest_data.get("owner", "admin"))

    def getUserRecordFromUsername(self, username: str) -> Union[Dict[str, Any], None]:
        """
        Get the user record from the database using the username without the password hash.

        Args:
            username (str): The username of the user.

        Returns:
            Union[Dict[str, Any], None]: The user record as a dictionary if found, None otherwise. The 'hash' field is removed from the returned dictionary.
        """
        ret: Optional[Dict[str, Any]] = self.findInDb("pollenisator", "users", {"username": username}, False)
        if ret is None:
            return None
        if isinstance(ret, dict):
            if "hash" in ret.keys():
                del ret["hash"] # pylint: disable=unsupported-delete-operation
        return ret

    def copyDb(self, fromCopyUUID: str, toCopyName: str, checkPentestName: bool = True) -> Tuple[str, int]:
        """
        Copy a database.

        Args:
            fromCopyUUID (str): The UUID of the database to be copied.
            toCopyName (str): The new pentset name of the new database.
            checkPentestName (bool, optional): Whether to check if the pentest name exists. Defaults to True.

        Returns:
            Tuple[str, int]: A tuple containing a message and a status code. The message indicates the result of the operation, and the status code is a HTTP-like status code.
        """
        self.connect()
        if fromCopyUUID == "":
            return "database to copy : empty name", 400
        if toCopyName == "":
            return "database destination name is empty", 400
        if self.client is None:
            return "No database connected", 400
        pentest_uuids = self.listPentestUuids()
        if pentest_uuids is None:
            return "API has trouble connecting to db. Check api server config.", 500
        if fromCopyUUID not in pentest_uuids and checkPentestName:
            return "database to copy : not found", 404
        pentest_data = self.findInDb("pollenisator", "pentests", {"uuid": fromCopyUUID }, False)
        if pentest_data is None:
            return "API has trouble connecting to db. Check api server config.", 500
        old_pentest_nom =  pentest_data.get("nom", "")
        major_version = ".".join(self.client.server_info()["version"].split(".")[:2])
        if float(major_version) < 4.2:
            succeed, msg = self.registerPentest(self.getPentestOwner(fromCopyUUID),
                    toCopyName, None, True, True)
            if not succeed:
                return msg, 403
            toCopyUUID = msg
            self.client.admin.command('copydb',
                                        fromdb=fromCopyUUID,
                                        todb=toCopyUUID)
            return "Database copied", 200
        else:
            outpath,status_code = self.dumpDb(fromCopyUUID)
            if status_code != 200:
                return outpath, status_code
            return self.importDatabase(self.getPentestOwner(fromCopyUUID), outpath, toCopyName, fromCopyUUID)

    def dumpDb(self, dbName: str, collection: str= "", directory: str="") -> Tuple[str,int]:
        """
        Export a database dump into the exports/ folder as a gzip archive.
        It uses the mongodump utility installed with mongodb-org-tools.

        Args:
            dbName (str): The database name to dump.
            collection (str = ""): The collection to dump. If not provided, the entire database is dumped. Defaults to "".
            directory (str = ""): The directory to save the gzip archive. If not provided, the archive is saved in the exports/ folder. Defaults to "".
        Raises:
            ValueError: If the database name is not found or is invalid.
            ValueError: If the database name is not alphanumeric.
        Returns:
            str: The path to the gzip archive.
        """
        from pollenisator.core.components.utils import execute
        pentest_uuids = self.listPentestUuids()
        if pentest_uuids is None:
            raise ValueError("API has trouble connecting to db. Check api server config.")
        if dbName is None or dbName not in pentest_uuids:
            raise ValueError("Database not found")
        if directory == "":
            dir_path = os.path.dirname(os.path.realpath(__file__))
            out_path = os.path.join(
                dir_path, "../../exports/", dbName if collection == "" else dbName+"_"+collection)
        else:
            out_path = os.path.join(directory, dbName)
        connectionString = '' if self.user == '' else "-u "+self.user + \
            " -p "+self.password + " --authenticationDatabase admin "
        cmd = "mongodump "+connectionString+"--host " + \
            self.host+"  --db "+dbName+" --archive="+out_path+".gz --gzip"
        if collection.strip() != "":
            cmd += " -c "+str(collection).strip()
        
        if self.ssl.strip() != "":
            cmd += " --ssl --sslPEMKeyFile "+self.ssldir+"/client.pem --sslCAFile " + \
                self.ssldir+"/ca.pem --sslAllowInvalidHostnames"
        logger.info("Dumping database with cmd : %s",cmd)
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            raw_stdout, raw_stderr = process.communicate(None)
            stdout = raw_stdout.decode('utf-8')
            stderr = raw_stderr.decode('utf-8')
            if str(stdout) != "":
                logger.debug(str(stdout))
            if str(stderr) != "":
                logger.error(str(stderr))
            if os.path.isfile(out_path+".gz"):
                return out_path+".gz", 200
            return stderr, 504
        except Exception as e:
            logger.error("ERROR in command execution of command %s: %s", cmd, e)
            process.kill()
            return "The backup utility had an error or is not installed.", 500
    
    @staticmethod
    def try_uuid(uuid_to_test: str) -> bool:
        """
        Validate a UUID string.

        Args:
            uuid_to_test (str): The UUID string to validate.

        Returns:
            bool: True if the string is a valid UUID, False otherwise.
        """
        try:
            uuid_obj = UUID(uuid_to_test, version=4)
        except ValueError:
            return False
        return str(uuid_obj) == uuid_to_test

    def importDatabase(self, owner: str, filename: str, pentest_name: str, orig_uuid: str) -> Tuple[str, int]:
        """
        Import a database dump into a pentest database.
        It uses the mongorestore utility installed with mongodb-org-tools.

        Args:
            owner (str): The owner's username.
            filename (str): The gzip archive name that was exported to be reimported.
            pentest_name (str): The name of the pentest to import the database into.
           orig_name (str): the original name of the database to import.

        Returns:
            Tuple[str, int]: A tuple containing a message and a status code. The message indicates the result of the operation, and the status code is a HTTP-like status code.
        """
        from pollenisator.core.components.utils import execute
        # if kwargs.get("nsTo", None) is not None:
        #     toDbName = kwargs.get("nsTo")
        # else:
        #     toDbName = os.path.splitext(os.path.basename(filename))[0]
        success, msg = self.registerPentest(owner, str(pentest_name), orig_uuid, True, False)
        new_pentest_uuid = msg
        if not self.try_uuid(new_pentest_uuid):
            return msg, 403
        pentest_uuids = self.listPentestUuids()
        if pentest_uuids is None:
            return "API has trouble connecting to db. Check api server config.", 500
        if new_pentest_uuid not in pentest_uuids:
            return "Database not found", 404
        if success:
            connectionString = '' if self.user == '' else "-u "+self.user + \
                " -p "+self.password + " --authenticationDatabase admin "
            cmd = "mongorestore "+connectionString+"--host " + \
                self.host+" --archive="+filename+" --gzip"
            if self.ssl.strip() != "":
                cmd += " --ssl --sslPEMKeyFile "+self.ssldir+"/client.pem --sslCAFile " + \
                    self.ssldir+"/ca.pem --sslAllowInvalidHostnames"
            if self.try_uuid(orig_uuid):
                cmd += " --nsFrom='"+orig_uuid+".*' --nsTo='"+new_pentest_uuid+".*'"
            execute(cmd, None, True)
        return msg, 200 if success else 403


    @overload
    def getRegisteredTags(self, pentest: str,  only_name: Literal[False] = False) ->  List[Dict[str, Any]]:
        ...
    @overload
    def getRegisteredTags(self, pentest: str,  only_name: Literal[True] = True) ->  List[str]:
        ...

    def getRegisteredTags(self, pentest: str, only_name: bool=True) -> Union[List[str], List[Dict[str, Any]]]:
        """
        Get the registered tag names for a specific pentest.

        Args:
            pentest (str): The name of the pentest.

        Returns:
            List[str]: A list of registered tag names. If no tags are found, an empty list is returned.
        """
        tags = self.findInDb(pentest,"settings", {"key":"tags"}, False)
        if tags is None:
            return []
        tags = tags.get("value", {})
        if isinstance(tags, str):
            tags = json.loads(tags)
        if only_name:
            pentest_tags = list(tags.keys())
            global_tags = list(self.getGlobalTags().keys())
        else:
            pentest_tags = [tags]
            global_tags = [self.getGlobalTags()]
        return global_tags+pentest_tags

    def getGlobalTags(self) -> Dict[str, Any]:
        """
        Get the global tags from the settings in the database.

        Returns:
            Dict[str, Any]: A dictionary of global tags. If no tags are found, an empty dictionary is returned.
        """
        dbclient = DBClient.getInstance()
        tags = dbclient.findInDb("pollenisator", "settings", {"key": "tags"}, False)
        if tags is not None:
            if isinstance(tags["value"], dict):
                return tags["value"]
            elif isinstance(tags["value"], str):
                try:
                    tagvalues: Union[str, Dict[str,Any]] = json.loads(tags["value"])
                    if isinstance(tagvalues, str):
                        returnval: Dict[str, Any] = json.loads(tagvalues)
                    else:
                        returnval = tagvalues
                    return returnval
                except json.JSONDecodeError:
                    pass
        return {}
        
    def getTagsGroups(self) -> List[List[str]]:
        """
        Returns groups of tags that may not be applied at the same time.

        Returns:
            List[List[str]]: A list of lists of strings. Each list of strings represents a group of tags. The first group is the global tags, and the second group is a single-element list containing "hidden".
        """
        tags = self.getGlobalTags()
        global_tags = [tag for tag in tags]
        return [global_tags, ["hidden"]]


    def doRegisterTag(self, pentest: str, tag: Tag) -> bool:
        """
        Register a new tag for a specific pentest.

        Args:
            pentest (str): The name of the pentest.
            tag (Tag): The tag to register.

        Returns:
            bool: True if the tag was successfully registered, False otherwise.
        """
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


    def send_notify(self, db: str, collection: str, iid: Union[str, List[str]], action: str, parentId: str = "") -> None:
        """
        Notify all observers of the modified record from database.
        Uses the observer's notify implementation. This implementation must take the same args as this.

        Args:
            db (str): The database where a document has been modified.
            collection (str): The collection where a document has been modified.
            iid Union(str, List[str]): The mongo ObjectId(s) of the document(s) that has been modified.
            action (str): The type of modification performed on this document ("insert", "update" or "delete").
            parentId (str, optional): A node parent id as str. Defaults to "".
        """
        from pollenisator.app_factory import notify_clients
        notify_clients({"iid": iid, "db": db, "collection": collection, "action": action, "parent": parentId, "time":datetime.datetime.now()})

    def do_upload(self, pentest: str, attachement_iid:  Union[Literal["unassigned"], str], filetype: str, upfile: Any, attached_to: Union[Literal["unassigned"], str]) -> Tuple[Dict[str, Any], int, str]:
        """
        Upload a file and attach it to a specific tool or defect in a pentest.

        Args:
            pentest (str): The name of the pentest.
            attachement_iid ( Union[Literal["unassigned"], str]): The id of attachment if replacing, else "unassigned".
            filetype (str): The type of the file, either 'result' or 'proof'.
            upfile (Any): The file to be uploaded.
            attached_to ( Union[Literal["unassigned"], str]): The id of the tool or defect to which the file is attached.

        Returns:
            Tuple[str, int, str]: A tuple containing a message indicating the result of the operation, a HTTP-like status code, and the path of the uploaded file if succeedeed only.
        """
        dbclient = DBClient.getInstance()
        local_path = os.path.normpath(os.path.join(utils.getMainDir(), "files"))
        try:
            os.makedirs(local_path)
        except FileExistsError:
            pass
        filepath = os.path.join(local_path, pentest, filetype, attached_to)
        if filetype == "result":
            if attached_to == "unassigned":
                return {"msg":"The given iid is unassigned", "attachment_id":None}, 400, ""
            res = dbclient.findInDb(pentest, "tools", {"_id": ObjectId(attached_to)}, False)
            if res is None:
                return {"msg":"The given iid does not match an existing tool", "attachment_id":None}, 404, ""

        elif filetype == "proof" and attached_to != "unassigned":
            res = dbclient.findInDb(pentest, "defects", {"_id": ObjectId(attached_to)}, False)
            if res is None:
                return {"msg":"The given iid does not match an existing defect", "attachment_id":None}, 404, ""
        elif filetype == "proof" and attached_to == "unassigned":
            pass
        elif filetype == "file" and attached_to != "unassigned":
            return {"msg":"Files cannot be assigned", "attachment_id":None}, 400, ""
        elif filetype == "file" and attached_to == "unassigned":
            pass
        else:
            return {"msg":"Filetype is not proof nor result", "attachment_id":None}, 400, ""
        if attachement_iid != "unassigned":
            replace = True
            attachment_id = str(attachement_iid)
        else:
            replace = False
            attachment_id = str(uuid4())
        try:
            os.makedirs(filepath)
        except FileExistsError:
            pass

        name, ext = os.path.splitext(upfile.filename.replace("/", "_"))
        ext = ext.replace("/","_")
        basename = os.path.basename(name)
        if filetype == "proof":
            if replace:
                name = basename+".png"
            else:
                name = basename+"-"+attachment_id +".png"
        elif filetype == "file":
            name = attachment_id + ext
        else:
            name = name + ext
        full_filepath = os.path.join(filepath, name)
        while os.path.exists(full_filepath) and not replace:
            attachment_id = str(uuid4())
            if filetype == "proof":
                name = basename+"-"+attachment_id+".png"
            elif filetype == "file":
                name = attachment_id+ext
            else:
                name = attachment_id+name
            full_filepath = os.path.join(filepath, attachment_id+name)
        with open(full_filepath, "wb") as f:
            f.write(upfile.stream.read())
        if filetype == "proof":
            im1 = Image.open(full_filepath)
            im1.save(full_filepath, format="png")
            upfile.stream.seek(0)
            if attached_to != "unassigned":
                dbclient.updateInDb(pentest, "defects", {"_id": ObjectId(attached_to)}, {"$addToSet":{"proofs":name}})
        return {"msg":name + " was successfully uploaded", "attachment_id":attachment_id}, 200, full_filepath
