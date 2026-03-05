"""
This module is a part of the Pollenisator project.
This module is responsible for managing the authentication information of the pentest.
"""
from typing import Any, Dict, List, Literal, Optional, Tuple, Union, cast
from typing_extensions import TypedDict
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.element import Element
from pymongo.results import InsertOneResult
from pollenisator.core.models.tool import Tool
from pollenisator.server.permission import permission
from pollenisator.server.permission import checkPentestPermission
from pollenisator.core.components.logger_config import logger
from .api_key_manager import ApiKeyManager
from werkzeug.exceptions import Unauthorized
import six

TypeEnumeration = Union[Literal["password"], Literal["cookie"]]
AuthInfoInsertResult = TypedDict('AuthInfoInsertResult', {'res': bool, 'iid': ObjectId})

class AuthInfo(Element):
    """
    Represents an authentication information object.

    Attributes:
        coll_name: collection name in pollenisator or pentest database

    """
    coll_name = 'auth'

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize an Auth object. If valuesFromDb is provided, it is used to initialize the object. 
        Otherwise, the object is initialized with default values.

        Args:
            pentest (str): The name of the current pentest.
            valuesFromDb (Optional[Dict[str, Any]], optional): The values from the database. Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.initialize(valuesFromDb.get("name", ""), valuesFromDb.get("value"), valuesFromDb.get("type"))

    def initialize(self, name: str = "", value: Optional[str] = None, type: Optional[TypeEnumeration] = None) -> 'AuthInfo':
        """
        Initialize this Authentication Info with the provided parameters.

        Args:
            name (str, optional): The name of this Authentication Info. Defaults to "".
            value (str, optional): The value of this Authentication Info. Defaults to None.
            type (str, optional): The type of this Authentication Info. Defaults to None.

        Returns:
            Auth: The initialized Authentication Info.
        """
        self.name = name
        self.value = value
        self.type = type
        return self

    def getData(self) -> Dict[str, Any]:
        """
        Get the data of this Auth object as a dictionary.

        Returns:
            Dict[str, Any]: The data of this Auth object.
        """
        return {"_id": self._id, "name":self.name, "value": self.value, "type":self.type}

    def addInDb(self) -> AuthInfoInsertResult:
        """
        Add this Auth object to the database and return the id of the inserted document.

        Returns:
            AuthInfoInsertResult: the result of the insert function
        """
        res: AuthInfoInsertResult = insert(self.pentest, self.getData())
        return res

    @classmethod
    def getTriggers(cls) -> List[str]:
        """
        Return the list of trigger declared here

        Returns:
            List[str]: A list of triggers.
        """
        return ["auth:password", "auth:cookie"]


@permission("pentester")
def insert(pentest: str, body: Dict[str, Any]) -> AuthInfoInsertResult:
    """
    Insert authentication information.

    Add an Auth Info.

    Args:
        pentest (str): The name of the current pentest.
        body (Dict[str, Any]): The authentication information.

    Returns:
        AuthInfoInsertResult: The result of the insert operation as a dict with result and iid.
    """
    auth = AuthInfo(pentest, body)
    dbclient = DBClient.getInstance()
    data = auth.getData()
    if "_id" in data:
        del data["_id"]
    ins_result = dbclient.insertInDb(pentest,
        AuthInfo.coll_name, data, notify=True)
    ins_result = cast(InsertOneResult, ins_result)
    iid = ins_result.inserted_id
    return {"res": True, "iid": iid}

@permission("pentester")
def link(pentest: str, auth_iid: str, object_iid: str) -> Tuple[str, int]:
    """
    Link an authentication information to an object.

    Args:
        pentest (str): The name of the current pentest.
        auth_iid (str): The id of the authentication information.
        object_iid (str): The id of the object to link the authentication information to.

    Returns:
        Tuple[str, int]: The result of the link operation or an error with status code.
    """
    #TODO swap to add checks #TODO lvl change
    dbclient = DBClient.getInstance()
    lookup = { "scopes":"network", "ips":"ip","ports":"port","waves":"wave"}
    lvl_found = None
    collection_found = None
    object_found = None
    for collection, lvl in lookup.items():
        res = dbclient.findInDb(pentest, collection, {"_id":ObjectId(object_iid)}, False)
        if res is not None:
            lvl_found = lvl
            object_found = res
            collection_found = collection
            break
    if lvl_found is None or object_found is None or collection_found is None:
        return "Object to link must be an existing wave,scope,ip or port", 400
    auth_d = dbclient.findInDb(pentest, AuthInfo.coll_name, {"_id":ObjectId(auth_iid)}, False)
    if auth_d is None:
        return f"Authentication info with iid {str(auth_iid)} was not found", 404
    if auth_d["type"].lower() == "cookie":
        command_lvl = "auth:cookie"
    if auth_d["type"].lower() == "password":
        command_lvl = "auth:password"
    object_found["infos"] = object_found.get("infos", {})
    object_found["infos"]["auth_cookie"] = auth_d.get("name", "")+"="+auth_d.get("value", "")+";"
    dbclient.updateInDb(pentest, collection_found, {"_id":ObjectId(object_found["_id"])}, {"$set":object_found})
    commands = dbclient.findInDb(pentest, "commands", {"lvl":command_lvl}, multi=True)
    if commands is None:
        return "No command found", 404
    for command in commands:
        tool = Tool(pentest).initialize(ObjectId(command["_id"]), object_found.get("wave", "Auth tools"),
                "", object_found.get("scope",""), object_found.get("ip",""), object_found.get("port",""), object_found.get("proto",""),
                lvl=lvl_found)
        tool.addInDb()
    return "OK", 200


@permission("user")
def create_api_key(body: Dict[str, Any], **kwargs: Any) -> Union[Dict[str, Any], Tuple[str, int]]:
    """
    Create a new API key for the authenticated user.
    
    Args:
        body: Request body containing name, expires_in_days, and permissions
        **kwargs: Contains token_info with user information
        
    Returns:
        API key information or error response
    """
    try:
        username = kwargs["token_info"]["sub"]
        name = body.get("name", "").strip()
        expires_in_days = body.get("expires_in_days")
        permissions = body.get("permissions", ["read"])
        pentest = body.get("pentest") or None
        
        # Validate input
        if not name:
            return "Name is required", 400
        
        if not expires_in_days or not isinstance(expires_in_days, int):
            return "expires_in_days is required and must be an integer", 400
            
        if not 1 <= expires_in_days <= 365:
            return "expires_in_days must be between 1 and 365", 400
        
        # Validate permissions
        valid_permissions = ["read", "write", "delete", "pentester", "user"]
        if not isinstance(permissions, list) or not all(p in valid_permissions for p in permissions):
            return f"Invalid permissions. Must be a list containing only: {valid_permissions}", 400
        
        # Validate pentest exists if provided
        if pentest is not None:
            dbclient = DBClient.getInstance()
            if dbclient.findInDb("pollenisator", "pentests", {"uuid": pentest}, False) is None:
                return "Pentest not found", 404
            if not checkPentestPermission(kwargs["token_info"], pentest, False):
                return "Forbidden : you are not allowed to access this pentest", 403
            # Force pentester permission for pentest-scoped keys
            if "pentester" not in permissions:
                permissions.append("pentester")
        
        # Ensure user scope is included
        if "user" not in permissions:
            permissions.append("user")
        
        # Create API key
        manager = ApiKeyManager()
        api_key_instance, plain_key = manager.create_api_key(
            user_id=username,
            name=name,
            expires_in_days=expires_in_days,
            permissions=permissions,
            pentest=pentest
        )
        
        return {
            "key_id": api_key_instance.key_id,
            "api_key": plain_key,
            "name": api_key_instance.name,
            "expires_at": api_key_instance.expires_at.isoformat(),
            "permissions": api_key_instance.permissions,
            "pentest": api_key_instance.pentest
        }, 201
        
    except ValueError as e:
        return str(e), 400
    except Exception as e:
        logger.error(f"Failed to create API key: {e}")
        return "Internal server error", 500


@permission("user")
def list_api_keys(**kwargs: Any) -> List[Dict[str, Any]]:
    """
    List all API keys for the authenticated user.
    
    Args:
        **kwargs: Contains token_info with user information
        
    Returns:
        List of API key information (excluding sensitive data)
    """
    try:
        username = kwargs["token_info"]["sub"]
        manager = ApiKeyManager()
        return manager.list_user_api_keys(username)
    except Exception as e:
        logger.error(f"Failed to list API keys: {e}")
        return []


@permission("user")
def revoke_api_key(key_id: str, **kwargs: Any) -> Union[str, Tuple[str, int]]:
    """
    Revoke an API key for the authenticated user.
    
    Args:
        key_id: The API key ID to revoke
        **kwargs: Contains token_info with user information
        
    Returns:
        Success message or error response
    """
    try:
        username = kwargs["token_info"]["sub"]
        
        if not key_id:
            return "key_id is required", 400
        
        manager = ApiKeyManager()
        success = manager.revoke_api_key(username, key_id)
        
        if success:
            return "API key revoked successfully", 200
        else:
            return "API key not found", 404
            
    except Exception as e:
        logger.error(f"Failed to revoke API key: {e}")
        return "Internal server error", 500

@permission("user")
def remove_api_key(key_id: str, **kwargs: Any) -> Union[str, Tuple[str, int]]:
    """
    Remove an API key for the authenticated user.
    
    Args:
        key_id: The API key ID to remove
        **kwargs: Contains token_info with user information
    Returns:
        Success message or error response
    """
    username = kwargs["token_info"]["sub"]
    
    if not key_id:
        return "key_id is required", 400
    
    manager = ApiKeyManager()
    success = manager.remove_api_key(username, key_id)
    if success:
        return "API key removed successfully", 200
    else:
        return "API key not found", 404
        


def verify_api_key_header(api_key: str) -> Optional[Dict[str, Any]]:
    """
    Verify API key from X-API-Key header for OpenAPI security.
    
    Args:
        api_key: The API key from the header
        
    Returns:
        Token info dictionary if valid, None otherwise
    """
    try:
        if not api_key:
            return None
            
        manager = ApiKeyManager()
        api_key_instance = manager.verify_api_key(api_key)
        
        if api_key_instance and api_key_instance.is_valid():
            # Return token info in the same format as JWT tokens
            token_info: Dict[str, Any] = {
                "sub": api_key_instance.user_id,
                "scope": api_key_instance.permissions,
                "api_key_id": api_key_instance.key_id,
                "exp": int(api_key_instance.expires_at.timestamp())
            }
            if api_key_instance.pentest:
                token_info["api_key_pentest"] = api_key_instance.pentest
            return token_info
        raise ValueError("Invalid API key")
    except Exception as e:
        logger.error(f"Failed to verify API key: {e}")
        return {}
    return {}
