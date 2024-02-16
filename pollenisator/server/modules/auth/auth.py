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
