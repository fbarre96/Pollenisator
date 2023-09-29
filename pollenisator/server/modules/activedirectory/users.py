# coding: utf-8

from __future__ import absolute_import
from pollenisator.core.components.logger_config import logger
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
from pollenisator.server.permission import permission
from pollenisator.server.servermodels.command import ServerCommand
from pollenisator.server.servermodels.tool import ServerTool

import pollenisator.server.modules.activedirectory.computers as Computer

class User(ServerElement):
    coll_name = "ActiveDirectory"
    name = "User"
    def __init__(self, pentest=None, valuesFromDb=None):
        if valuesFromDb is None:
            valuesFromDb = {}
        self.initialize(pentest, valuesFromDb.get("_id"), valuesFromDb.get("domain"), valuesFromDb.get("username"), valuesFromDb.get("password"),
            valuesFromDb.get("groups"), valuesFromDb.get("description"), valuesFromDb.get("infos", {}))

    def initialize(self, pentest, _id, domain=None, username=None, password=None,groups=None, description=None, infos=None):
        """User
        :param pentest: current pentest 
        :type pentest: str
        :param _id: iid of the object
        :type _id: str
        :param username: The username of this User.
        :type username: str
        :param password: The password of this User.
        :type password: str
        :param domain: The domain of this User.
        :type domain: str
        :param groups: The groups of this User.
        :type groups: List[str]
        :param description: The description of this User.
        :type description: str
        """
      
        self._id = _id
        self.username = username if username is not None else  ""
        self.password = password if password is not None else  ""
        self.domain = domain if domain is not None else  ""
        self.groups = groups
        self.description = description
        self.infos =  infos if infos is not None else {}
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        return self
  
    def __str__(self):
        """
        Get a string representation of a defect.

        Returns:
            Returns the defect +title.
        """
        return self.domain+"\\"+self.username 

    def getData(self):
        return {"_id": self._id, "username":self.username, "password": self.password, "domain":self.domain,
         "groups": self.groups, "description":self.description, "infos":self.infos}

    
    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "user"
        ds = dbclient.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            # disabling this error as it is an abstract function
            yield cls(pentest,d)  #  pylint: disable=no-value-for-parameter
    
    @classmethod
    def fetchObject(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "user"
        d = dbclient.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls(pentest, d)

    def addInDb(self):
        return insert(self.pentest, self.getData())

    @classmethod
    def replaceCommandVariables(cls, pentest, command, data):
        command = command.replace("|username|", data.get("username", ""))
        command = command.replace("|domain|", "" if data.get("domain", "") is None else data.get("domain", ""))
        command = command.replace("|password|", data.get("password", ""))
        return command

    def checkAllTriggers(self):
        self.add_user_checks()
        
    def add_user_checks(self):
        if self.password.strip() != "":
            self.addCheck("AD:onNewValidUser", {"user":self})
        else:
            self.addCheck("AD:onNewUserFound", {"user":self})

    def addCheck(self, lvl, info):
        checks = CheckItem.fetchObjects({"lvl":lvl})
        user_o = info.get("user")
        if user_o is None:
            logger.error("User was not found when trying to add ActiveDirectory tool ")
            return
        username = user_o.username if user_o.username is not None else ""
        password = user_o.password if user_o.password is not None else ""
        domain = user_o.domain if user_o.domain is not None else ""
        dbclient = DBClient.getInstance()
        dc_computer = dbclient.findInDb(self.pentest, "ActiveDirectory", {"type":"computer", "domain":domain, "infos.is_dc":True}, False)
        dc_ip = None if dc_computer is None else dc_computer.get("ip")
        infos = {"username":username, "password":password, "domain":domain, "dc_ip":dc_ip}
        if dc_ip is None:
            return
        for check in checks:
            CheckInstance.createFromCheckItem(self.pentest, check, str(self._id), "user", infos=infos)

    @classmethod
    def getTriggers(cls):
        """
        Return the list of trigger declared here
        """
        return ["AD:onNewValidUser", "AD:onNewUserFound"]

    @property
    def username(self):
        """Gets the username of this User.


        :return: The username of this User.
        :rtype: str
        """
        return self._username

    @username.setter
    def username(self, username):
        """Sets the username of this User.


        :param username: The username of this User.
        :type username: str
        """

        self._username = username

    @property
    def password(self):
        """Gets the password of this User.


        :return: The password of this User.
        :rtype: str
        """
        return self._password

    @password.setter
    def password(self, password):
        """Sets the password of this User.


        :param password: The password of this User.
        :type password: str
        """

        self._password = password

    @property
    def domain(self):
        """Gets the domain of this User.


        :return: The domain of this User.
        :rtype: str
        """
        return self._domain

    @domain.setter
    def domain(self, domain):
        """Sets the domain of this User.


        :param domain: The domain of this User.
        :type domain: str
        """

        self._domain = domain

    @property
    def groups(self):
        """Gets the groups of this User.


        :return: The groups of this User.
        :rtype: List[str]
        """
        return self._groups

    @groups.setter
    def groups(self, groups):
        """Sets the groups of this User.


        :param groups: The groups of this User.
        :type groups: List[str]
        """
        self._groups = groups

    @property
    def description(self):
        """Gets the description of this User.


        :return: The description of this User.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this User.


        :param description: The description of this User.
        :type description: str
        """

        self._description = description


@permission("pentester")
def delete(pentest, user_iid):
    """delete user

    Delete an Active Directory user # noqa: E501

    :param pentest: 
    :type pentest: str
    :param user_iid: 
    :type user_iid: str

    :rtype: Union[None, Tuple[None, int], Tuple[None, int, Dict[str, str]]
    """
    dbclient = DBClient.getInstance()
    user_dic = dbclient.findInDb(pentest, "ActiveDirectory", {"_id":ObjectId(user_iid), "type":"user"}, False)
    if user_dic is None:
        return 0
    computers = dbclient.findInDb(pentest, "ActiveDirectory",
                                {"type":"computer", "$or": [ { "users": str(user_iid) }, { "admins": str(user_iid) } ] }, True)
    for computer in computers:
        if str(user_iid) in computer["users"]:
            computer["users"].remove(str(user_iid))
            Computer.update(pentest, computer["_id"], computer)
        if str(user_iid) in computer["admins"]:
            computer["admins"].remove(str(user_iid))
            Computer.update(pentest, computer["_id"], computer)
    res = dbclient.deleteFromDb(pentest, "ActiveDirectory", {"_id": ObjectId(str(user_iid)), "type":"user"}, False)
    if res is None:
        return 0
    else:
        return res

@permission("pentester")
def insert(pentest, body):
    """insert user

    Add an Active Directory user # noqa: E501

    :param pentest: pentest name
    :type pentest: str
    :param user: 
    :type user: dict | bytes

    :rtype: Union[None, Tuple[None, int], Tuple[None, int, Dict[str, str]]
    """
    user = User(pentest, body)
    dbclient = DBClient.getInstance()
    domain = user.domain.lower() if user.domain is not None else ""
    username = user.username.lower() if user.username is not None else ""
    password = user.password if user.password is not None else ""
    existing = dbclient.findInDb(pentest, 
        "ActiveDirectory", {"type":"user", "domain":domain, "username":username}, False)
    if existing is not None:
        if existing["password"] != "":
            return {"res": False, "iid": existing["_id"]}
        else:
            dbclient.updateInDb(pentest, "ActiveDirectory", {"_id":ObjectId(existing["_id"])}, {"$set":{"password":password}})
            return {"res": False, "iid": existing["_id"]}
    if "_id" in body:
        del body["_id"]
    body["type"] = "user"
    
    ins_result = dbclient.insertInDb(pentest, 
        "ActiveDirectory", body, True)
    iid = ins_result.inserted_id
    user._id = iid
    user.add_user_checks()
    
    return {"res": True, "iid": iid}

@permission("pentester")
def update(pentest, user_iid, body):
    """update user

    Update an Active Directory user # noqa: E501

    :param pentest: 
    :type pentest: str
    :param user_iid: 
    :type user_iid: str
    :param user: 
    :type user: dict | bytes

    :rtype: Union[None, Tuple[None, int], Tuple[None, int, Dict[str, str]]
    """
    user = User(pentest, body)
    user.username = user.username.lower()
    user.domain = user.domain.lower()
    dbclient = DBClient.getInstance()
    user_existing = User.fetchObject(pentest, {"_id": ObjectId(user_iid)})
    if user_existing.username != user.username  and user_existing.domain != user.domain:
        return "Forbidden", 403
    if "type" in body:
        del body["type"]
    if "_id" in body:
        del body["_id"]
    if str(user.description) != "None" or str(user.description) != "":
        del body["description"]

    dbclient.updateInDb(pentest, "ActiveDirectory", {"_id": ObjectId(user_iid), "type":"user"}, {"$set": body}, False, True)
    return True
