# coding: utf-8

from __future__ import absolute_import
import logging
from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.server.ServerModels.Element import ServerElement
from pollenisator.server.permission import permission
from pollenisator.server.ServerModels.Command import ServerCommand
from pollenisator.server.ServerModels.Tool import ServerTool

import pollenisator.server.modules.ActiveDirectory.computers as Computer

class User(ServerElement):
    coll_name = "ActiveDirectory"
    
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
        mongoInstance = MongoCalendar.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        return self
  
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
        mongoInstance = MongoCalendar.getInstance()
        pipeline["type"] = "user"
        ds = mongoInstance.findInDb(pentest, cls.coll_name, pipeline, True)
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
        mongoInstance = MongoCalendar.getInstance()
        pipeline["type"] = "user"
        d = mongoInstance.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls(pentest, d)

    def addInDb(self):
        return insert(self.pentest, self.getData())

    def addTool(self, lvl, info):
        commands = ServerCommand.fetchObjects({"lvl":lvl}, targetdb=self.pentest)
        user_o = info.get("user")
        if user_o is None:
            logging.error("User was not found when trying to add ActiveDirectory tool ")
            return
        username = user_o.username if user_o.username is not None else ""
        password = user_o.password if user_o.password is not None else ""
        domain = user_o.domain if user_o.domain is not None else ""
        mongoInstance = MongoCalendar.getInstance()
        dc_computer = mongoInstance.findInDb(self.pentest, "ActiveDirectory", {"type":"computer", "domain":domain, "infos.is_dc":True}, False)
        dc_ip = None if dc_computer is None else dc_computer.get("ip")
        infos = {"username":username, "password":password, "domain":domain, "dc_ip":dc_ip}
        if dc_ip is None:
            return
        wave_d = mongoInstance.findInDb(self.pentest, "waves", {"wave":{"$ne":"Imported"}}, False)
        for command in commands:
            newTool = ServerTool(self.pentest)
            newTool.initialize(command.getId(), wave=wave_d["wave"],
                              name=command.name+":"+str(username), lvl=lvl, infos=infos)
            newTool.addInDb()

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
    mongoInstance = MongoCalendar.getInstance()
    user_dic = mongoInstance.findInDb(pentest, "ActiveDirectory", {"_id":ObjectId(user_iid), "type":"user"}, False)
    if user_dic is None:
        return 0
    computers = mongoInstance.findInDb(pentest, "ActiveDirectory",
                                {"type":"computer", "$or": [ { "users": str(user_iid) }, { "admins": str(user_iid) } ] }, True)
    for computer in computers:
        if str(user_iid) in computer["users"]:
            computer["users"].remove(str(user_iid))
            Computer.update(pentest, computer["_id"], computer)
        if str(user_iid) in computer["admins"]:
            computer["admins"].remove(str(user_iid))
            Computer.update(pentest, computer["_id"], computer)
    res = mongoInstance.deleteFromDb(pentest, "ActiveDirectory", {"_id": ObjectId(str(user_iid)), "type":"user"}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count

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
    mongoInstance = MongoCalendar.getInstance()
    domain = user.domain if user.domain is not None else ""
    username = user.username if user.username is not None else ""
    password = user.password if user.password is not None else ""
    existing = mongoInstance.findInDb(pentest, 
        "ActiveDirectory", {"type":"user", "domain":domain, "username":username, "password":password}, False)
    if existing is not None:
        if existing["password"] != "":
            return {"res": False, "iid": existing["_id"]}
        else:
            mongoInstance.updateInDb(pentest, "ActiveDirectory", {"_id":ObjectId(existing["_id"])}, {"$set":{"password":password}})
            return {"res": False, "iid": existing["_id"]}
    if "_id" in body:
        del body["_id"]
    body["type"] = "user"
    
    ins_result = mongoInstance.insertInDb(pentest, 
        "ActiveDirectory", body, True)
    if password.strip() != "":
        user.addTool("AD:onNewValidUser", {"user":user})
    else:
        user.addTool("AD:onNewUserFound", {"user":user})
    iid = ins_result.inserted_id
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
    mongoInstance = MongoCalendar.getInstance()
    user_existing = User.fetchObject(pentest, {"_id": ObjectId(user_iid)})
    if user_existing.username != user.username  and user_existing.domain != user.domain:
        return "Forbidden", 403
    if "type" in body:
        del body["type"]
    if "_id" in body:
        del body["_id"]
    mongoInstance.updateInDb(pentest, "ActiveDirectory", {"_id": ObjectId(user_iid), "type":"user"}, {"$set": body}, False, True)
    return True
