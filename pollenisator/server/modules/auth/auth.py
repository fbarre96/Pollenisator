from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.server.servermodels.tool import ServerTool
from pollenisator.server.permission import permission

class AuthInfo(ServerElement):
    coll_name = 'auth'
    def __init__(self, pentest=None, valuesFromDb=None):
        if valuesFromDb is None:
            valuesFromDb = {}
        self.initialize(pentest, valuesFromDb.get("_id"), valuesFromDb.get("name"), valuesFromDb.get("value"), valuesFromDb.get("type"))

    
    def initialize(self, pentest, _id, name=None, value=None, type=None):
        """User
        :param pentest: current pentest 
        :type pentest: str
        :param _id: iid of the object
        :type _id: str
        :param name: The name of this Authentication Info.
        :type name: str
        :param value: The value of this Authentication Info.
        :type value: str
        :param type: The type of this Authentication Info.
        :type type: str
        """
      
        self._id = _id
        self.name = name
        self.value = value
        self.type = type
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.pentestName != "":
            self.pentest = dbclient.pentestName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        return self
  
    def getData(self):
        return {"_id": self._id, "name":self.name, "value": self.value, "type":self.type}

    def addInDb(self):
        return insert(self.pentest, self.getData())

@permission("user")
def getModuleInfo():
    return {"registerLvls": ["auth:password", "auth:cookie"]}

@permission("pentester")
def insert(pentest, body):
    """insert authentication information

    Add an Auth Info # noqa: E501

    :param pentest: pentest name
    :type pentest: str
    :param user: 
    :type user: dict | bytes

    :rtype: Union[None, Tuple[None, int], Tuple[None, int, Dict[str, str]]
    """
    auth = AuthInfo(pentest, body)
    dbclient = DBClient.getInstance()
    if "_id" in body:
        del body["_id"]
    
    ins_result = dbclient.insertInDb(pentest,
        AuthInfo.coll_name, body, True)
    iid = ins_result.inserted_id
    return {"res": True, "iid": iid}

@permission("pentester")
def link(pentest, auth_iid, object_iid):
    #TODO swap to add checks
    dbclient = DBClient.getInstance()
    lookup = { "scopes":"network", "ips":"ip","ports":"port","waves":"wave"}
    lvl_found = None
    collection_found = None
    object_found = None
    for collection,lvl in lookup.items():
        res = dbclient.findInDb(pentest, collection, {"_id":ObjectId(object_iid)}, False)
        if res is not None:
            lvl_found = lvl
            object_found = res
            collection_found = collection
            break
    if lvl_found is None:
        return "Object to link must be an existing wave,scope,ip or port", 400
    auth_d = dbclient.findInDb(pentest, AuthInfo.coll_name, {"_id":ObjectId(auth_iid)}, False)
    if auth_d is None:
        return f"Authentication info with iid {str(auth_iid)} was not found", 404
    if auth_d["type"].lower() == "cookie":
        command_lvl = "auth:cookie"
    if auth_d["type"].lower() == "password":
        command_lvl = "auth:password"
    object_found["infos"]["auth_cookie"] = auth_d["name"]+"="+auth_d["value"]+";"
    dbclient.updateInDb(pentest, collection_found, {"_id":ObjectId(object_found["_id"])}, {"$set":object_found})
    commands = dbclient.findInDb(pentest, "commands", {"lvl":command_lvl}, multi=True)
    if commands is None:
        return "No command found", 404
    for command in commands:
        tool = ServerTool(pentest).initialize(str(command["_id"]), object_found.get("wave", "Auth tools"),
                "", object_found.get("scope",""), object_found.get("ip",""), object_found.get("port",""), object_found.get("proto",""),
                lvl=lvl)
        tool.addInDb()
    return "OK", 200