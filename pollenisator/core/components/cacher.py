"""
Module for caching database query results using Redis.
"""
import os
from typing import Union, Dict, Any, List, Tuple, Optional
import hashlib
import json
import inspect
import pymongo
import redis
from bson import ObjectId
import pollenisator.core.components.utils as utils
from pollenisator.core.components.logger_config import logger


class Cacher:
    """
    A class to handle caching of database query results using Redis.
    """

    def __init__(self):
        self.cache_collections = ["ports", "ips",
                                  "checkinstances", "commands", "pentests"]
        self.redis = None
        self.key_expiry = 20  # seconds

    def connect_cache(self) -> None:
        """
        Connect to the Redis cache.

        This function attempts to connect to a Redis server using the host and port
        specified in the environment variables.
        Usable environment variables are REDIS_HOST and REDIS_PORT. 
        If the connection fails, it logs an error and continues without the cache,
        which may slow down the application.
        """
        try:
            if self.redis is None:
                redis_port = int(os.environ.get("REDIS_PORT", 6379))
                redis_host = os.environ.get("REDIS_HOST", "127.0.0.1")
                self.redis = redis.Redis(
                    host=redis_host, port=redis_port, decode_responses=True)
        except redis.exceptions.ConnectionError as _e:
            logger.error(
                "No redis server found, continuing without will slow down the app.")
            self.redis = None

    def deleteKeyWithPipeline(self, pentest: str, collection: str, pipeline: dict) -> None:
        """
        Delete a key from the Redis cache based on the provided pentest, collection, and pipeline.

        Args:
            pentest (str): The pentest identifier.
            collection (str): The collection name.
            pipeline (dict): The pipeline dictionary used to construct the cache key.

        Returns:
            None
        """
        if self.redis is None:
            return
        if collection in self.cache_collections:
            if len(pipeline) == 1 and isinstance(pipeline[list(pipeline.keys())[0]], ObjectId):
                cache_key = pentest+"."+collection+"." + \
                    str(pipeline[list(pipeline.keys())[0]])
            else:
                cache_key = pentest+"."+collection+"." + \
                    hashlib.md5(json.dumps(
                        pipeline, cls=utils.JSONEncoder).encode()).hexdigest()
            if self.redis:
                try:
                    self.redis.delete(cache_key)
                except redis.exceptions.ConnectionError as _e:
                    logger.warning("Failed to connect to redis")
                    self.redis = None

    def cacheSet(self, pentest: str, collection: str, oid: Union[str, ObjectId],
                 values: Union[Dict[str, Any], List[Dict[str, Any]]]) -> None:
        """
        Set a value in the Redis cache.

        Args:
            pentest (str): The pentest identifier.
            collection (str): The collection name.
            oid (Union[str, ObjectId]): The identifier for the value to be cached.
            values (dict): The value to be cached.

        Returns:
            None
        """
        if self.redis is None:
            return
        if collection in self.cache_collections:
            cache_key = pentest+"."+collection+"."+str(oid)
            try:
                self.redis.set(cache_key, json.dumps(
                    values, cls=utils.JSONEncoder), ex=self.key_expiry)
            except redis.exceptions.ConnectionError as _e:
                logger.warning("Failed to connect to redis")

    def cacheGet(self, pentest: str, collection: str, pipeline: dict, multi: bool) \
                -> Tuple[Union[Dict[str, Any], List[Dict[str, Any]], None], Optional[str]]:
        """
        Retrieve a value from the Redis cache based on the provided 
            pentest, collection, and pipeline.

        Args:
            pentest (str): The pentest identifier.
            collection (str): The collection name.
            pipeline (dict): The pipeline dictionary used to construct the cache key.
            multi (bool): A flag indicating whether to expect multiple results.

        Returns:
            Tuple[Union[Dict[str, Any], List[Dict[str, Any]]], Optional[str]]: a tuple with
                0 : The cached value if found, otherwise None.
                1 : The cache key used for retrieval, or None if not applicable.
        """
        if self.redis is None:
            return None, None
        cache_key: Optional[str] = None
        if collection in self.cache_collections:
            if not multi and len(pipeline) == 1 and isinstance(pipeline[list(pipeline.keys())[0]], ObjectId):
                cache_key = pentest+"."+collection+"." + \
                    str(pipeline[list(pipeline.keys())[0]])
            elif not multi:
                cache_key = pentest+"."+collection+"." + \
                    hashlib.md5(json.dumps(
                        pipeline, cls=utils.JSONEncoder).encode()).hexdigest()
        if cache_key is None:
            return None, None
        try:
            res_redis: Any = self.redis.get(cache_key)
            if res_redis:
                res: Union[Dict[str, Any], List[Dict[str, Any]],
                           None] = json.loads(res_redis, cls=utils.JSONDecoder)
                return res, cache_key
        except redis.exceptions.ConnectionError:
            logger.warning("Failed to get from redis")
        return None, cache_key

    def setCacheFromFindResult(self, cache_key: str, find_result: Union[pymongo.cursor.Cursor, None, List[Dict[str, Any]]])\
          -> Union[Dict[str, Any], List[Dict[str, Any]], None, pymongo.cursor.Cursor]:
        """
        Cache the result of a database find operation in Redis.
        Args:
            cache_key (str): The key under which to store the cached result.
            find_result (Union[pymongo.cursor.Cursor, None, List[Dict[str, Any]]]): 
                The result of the database find operation.

        Returns:
            Union[Dict[str, Any], List[Dict[str, Any]], None, pymongo.cursor.Cursor]: 
                The value that was cached, or None if caching was not performed.
        """
        if self.redis is None:
            return None
        if inspect.isgenerator(find_result) or isinstance(find_result, pymongo.cursor.Cursor):
            return_value = [r for r in find_result]
        elif find_result is None:
            return_value = None
        else:
            return_value = find_result
        store = json.dumps(return_value, cls=utils.JSONEncoder)
        try:
            self.redis.set(cache_key, store, ex=self.key_expiry)
        except redis.exceptions.ConnectionError as e:
            logger.warning("Failed to set to redis, connection error %s", e)
        return return_value
