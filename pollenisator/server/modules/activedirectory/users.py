"""Active directory module to handle users"""
# coding: utf-8

from __future__ import absolute_import
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union, cast
from typing_extensions import TypedDict
from pollenisator.core.components.logger_config import logger
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.element import Element
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
from pollenisator.server.permission import permission

import pollenisator.server.modules.activedirectory.computers as computers

UserInsertResult = TypedDict('UserInsertResult', {'res': bool, 'iid': ObjectId})

class User(Element):
    """
    Class to describe an Active Directory user

    Attributes:
        coll_name: collection name in database
        command_variables: list of variables that can be used in commands
    """
    coll_name = "users"
    command_variables = ["username","domain","password"]

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize a User object. If values from the database are provided, they are used to initialize the object. 
        Otherwise, the object is initialized with default values.

        Args:
            pentest (Optional[str], optional): The name of the current pentest. Defaults to None.
            valuesFromDb (Optional[Dict[str, Any]], optional): The values from the database. Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.initialize( valuesFromDb.get("domain"), valuesFromDb.get("username"), valuesFromDb.get("password"),
            valuesFromDb.get("groups"), valuesFromDb.get("description"), valuesFromDb.get("infos", {}))

    def initialize(self, domain: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, groups: Optional[List[str]] = None, description: Optional[str] = None, infos: Optional[Dict[str, Any]] = None) -> 'User':
        """
        Initialize a User object. If parameters are provided, they are used to initialize the object. 
        Otherwise, the object is initialized with default values.

        Args:
            domain (Optional[str], optional): The domain of this User. Defaults to None.
            username (Optional[str], optional): The username of this User. Defaults to None.
            password (Optional[str], optional): The password of this User. Defaults to None.
            groups (Optional[List[str]], optional): The groups of this User. Defaults to None.
            description (Optional[str], optional): The description of this User. Defaults to None.
            infos (Optional[Dict[str, Any]], optional): Additional information about this User. Defaults to None.

        Returns:
            User: The initialized User object.
        """

        self.username = username if username is not None else  ""
        self.password = password if password is not None else  ""
        self.domain = domain if domain is not None else  ""
        self.groups = groups if groups is not None else []
        self.description = description if description is not None else  ""
        self.infos =  infos if infos is not None else {}
        return self

    def __str__(self) -> str:
        """
        Get a string representation of a user.

        Returns:
            Returns the user domain\\username.
        """
        return str(self.domain)+"\\"+str(self.username)

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Get the attributes of the User class that can be used for text search.

        Returns:
            List[str]: A list of attribute names.
        """
        return ["domain", "username"]

    def getData(self) -> Dict[str, Any]:
        """
        Get the data of this User object as a dictionary.

        Returns:
            Dict[str, Any]: The data of this User object.
        """
        return {"_id": self._id, "username":self.username, "password": self.password, "domain":self.domain,
         "groups": self.groups, "description":self.description, "infos":self.infos}


    @classmethod
    def fetchObjects(cls, pentest: str, pipeline: Dict[str, Any]) -> Optional[Iterator['User']]:
        """
        Fetch many users from the database and return a Cursor to iterate over User objects.

        Args:
            pentest (str): The name of the current pentest.
            pipeline (Dict[str, Any]): A MongoDB search pipeline.

        Returns:
            Optional[Iterator[User]]: A cursor to iterate over User objects, or None if no users are found.
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "user"
        ds = dbclient.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            yield User(pentest,d)

    @classmethod
    def fetchObject(cls, pentest: str, pipeline: Dict[str, Any]) -> Optional['User']:
        """
        Fetch a user from the database and return a User object. If no user is found, None is returned.

        Args:
            pentest (str): The name of the current pentest.
            pipeline (Dict[str, Any]): A MongoDB search pipeline.

        Returns:
            Optional[User]: A User object, or None if no user is found.
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "user"
        d = dbclient.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return User(pentest, d)

    def addInDb(self) -> UserInsertResult:
        """
        Add this User object to the database and return the id of the inserted document.

        Returns:
            UserInsertResult: The UserInsertResult of the inserted document.
        """
        dbclient = DBClient.getInstance()
        domain = self.domain.lower() if self.domain is not None else ""
        username = self.username.lower() if self.username is not None else ""
        username = username.strip()
        password = self.password if self.password is not None else ""
        password = password.strip()
        existing = User.fetchObject(self.pentest, {"type":"user", "domain":{"$regex":domain}, "username":username})
        if existing is not None:
            if existing.password != "":
                return {"res": False, "iid": existing.getId()}
            else:
                existing.infos |= self.infos
                existing.password = password
                existing.update()
                return {"res": False, "iid": existing.getId()}
        data = self.getData()
        if "_id" in data:
            del data["_id"]
        data["type"] = "user"
        
        ins_result = dbclient.insertInDb(self.pentest, 
            "users", data)
        iid = ins_result.inserted_id
        self._id = iid
        self.add_user_checks()
        return {"res": True, "iid": iid}


    def deleteFromDb(self) -> int:
        """
        Delete this User object from the database and return the result of the deletion operation.

        Returns:
            int: The result count of the deletion operation.
        """
        dbclient = DBClient.getInstance()
        computers_found = computers.Computer.fetchObjects(self.pentest, { "$or": [ { "users": ObjectId(self._id) }, { "admins": ObjectId(self._id) } ] })
        for computer_o in computers_found:
            if ObjectId(self.getId()) in computer_o.users:
                computer_o.users.remove(ObjectId(self.getId()))
                computer_o.update()
            if self.getId() in computer_o.admins:
                computer_o.admins.remove(ObjectId(self.getId()))
                computer_o.update()
        res = dbclient.deleteFromDb(self.pentest, "users", {"_id": ObjectId(str(self.getId())), "type":"user"}, False)
        if res is None:
            return 0
        else:
            return res
        
    
    def getUserData(self) -> Dict[str, Any]:
        """
        Get the  data for the user.

        Returns:
            Dict[str, Any]: A dictionary containing the user useful data.
        """
        ret: Dict[str, Any] = {}
        ret["user"] = self.getData()
        ret["checks"] = {}
      
        ### checks data
        checks = CheckInstance.fetchObjects(self.pentest, {"target_iid": ObjectId(self.getId()), "target_type": "user"})
        if checks is None:
            return ret
        for check in checks:
            check = cast(CheckInstance, check)
            result = check.getCheckInstanceInformation()
            if result is not None:
                ret["checks"][str(check.getId())] = result
        return ret

    def update(self) -> None:
        """
        Update this User object in the database.
        """
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(self.pentest, "users", {"_id": ObjectId(self.getId()), "type":"user"}, {"$set": self.getData()})

    @classmethod
    def replaceCommandVariables(cls, _pentest: str, command: str, data: Dict[str, Any]) -> str:
        """
        Replace variables in the command with the corresponding values from the data.

        Args:
            pentest (str): The name of the current pentest.
            command (str): The command with variables to be replaced.
            data (Dict[str, str]): The data containing the values for the variables.

        Returns:
            str: The command with variables replaced by their corresponding values.
        """
        command = command.replace("|username|", data.get("username", ""))
        command = command.replace("|domain|", "" if data.get("domain", "") is None else data.get("domain", ""))
        command = command.replace("|password|", data.get("password", ""))
        return command

    def checkAllTriggers(self) -> None:
        """
        Add the appropriate checks for this user.
        """
        self.add_user_checks()

    def add_user_checks(self) -> None:
        """
        Add the appropriate user-related checks for this user.
        """
        if self.password.strip() != "":
            self.addCheck("AD:onNewValidUser", {"user":self})
        else:
            self.addCheck("AD:onNewUserFound", {"user":self})

    def addCheck(self, lvl: str, info: Dict[str, Any]) -> None:
        """
        Add a check to this User based on the provided level and info.

        Args:
            lvl (str): The level of the check.
            info (Dict[str, Any]): The information needed to add the check.
        """
        checks = CheckItem.fetchObjects("pollenisator", {"lvl":lvl})
        user_o = info.get("user")
        if user_o is None:
            logger.error("User was not found when trying to add ActiveDirectory tool ")
            return
        username = user_o.username if user_o.username is not None else ""
        password = user_o.password if user_o.password is not None else ""
        domain = user_o.domain if user_o.domain is not None else ""
        dbclient = DBClient.getInstance()
        dc_computer = dbclient.findInDb(self.pentest, "computers", {"type":"computer", "domain":domain, "infos.is_dc":True}, False)
        dc_ip = None if dc_computer is None else dc_computer.get("ip")
        infos = {"username":username, "password":password, "domain":domain, "dc_ip":dc_ip}
        if dc_ip is None:
            return
        for check in checks:
            CheckInstance.createFromCheckItem(self.pentest, check, ObjectId(self._id), "user", infos=infos)

    @classmethod
    def getTriggers(cls) -> List[str]:
        """
        Return the list of trigger declared here

        Returns:
            List[str]: The list of triggers
        """
        return ["AD:onNewValidUser", "AD:onNewUserFound"]

    @property
    def username(self) -> str:
        """Gets the username of this User.

        Returns:
            str: The username of this User.
        """
        return self._username

    @username.setter
    def username(self, username: str):
        """Sets the username of this User.

        Args:
            username (str): The username of this User.
        """
        self._username = username

    @property
    def password(self) -> str:
        """Gets the password of this User.

        Returns:
            str: The password of this User.
        """
        return self._password

    @password.setter
    def password(self, password: str):
        """Sets the password of this User.

        Args:
            password (str): The password of this User.
        """

        self._password = password

    @property
    def domain(self) -> str:
        """Gets the domain of this User.

        Returns:
            str: The domain of this User.
        """
        return self._domain

    @domain.setter
    def domain(self, domain: str):
        """Sets the domain of this User.

        Args:
            domain (str): The domain of this User.
        """

        self._domain = domain

    @property
    def groups(self) -> List[str]:
        """Gets the groups of this User.

        Returns:
            List[str]: The groups of this User.
        """
        return self._groups

    @groups.setter
    def groups(self, groups: List[str]):
        """Sets the groups of this User.

        Args:
            groups (List[str]): The groups of this User.
        """
        self._groups = groups

    @property
    def description(self) -> str:
        """Gets the description of this User.
        
        Returns:
            str: The description of this User.
        """
        return self._description

    @description.setter
    def description(self, description: str):
        """Sets the description of this User.

        Args:
            description (str): The description of this User.
        """
        self._description = description


@permission("pentester")
def delete(pentest: str, user_iid: str) -> int:
    """
    Delete an Active Directory user.

    Args:
        pentest (str): The name of the current pentest.
        user_iid (str): The id of the user to be deleted.

    Returns:
        int: The result of the delete operation.
    """
    user = User.fetchObject(pentest, {"_id":ObjectId(user_iid)})
    if user is None:
        return 0
    return user.deleteFromDb()
    

@permission("pentester")
def insert(pentest:str, body: Dict[str, Any]) -> UserInsertResult:
    """
    Insert the user given in the body in the database using

    Args:
        pentest (str): The name of the current pentest.
        body (Dict[str, Any]): The new user data.

    Returns:
        UserInsertResult: The user inserted dictionnary with "res" and "iid"
    """
    user = User(pentest, body)
    return user.addInDb()

@permission("pentester")
def update(pentest: str, user_iid: str, body: Dict[str, Any]) -> Union[bool, Tuple[str, int]]:
    """
    Update an Active Directory user.

    Args:
        pentest (str): The name of the current pentest.
        user_iid (str): The id of the user to be updated.
        body (Union[dict, bytes]): The new user data.

    Returns:
        Union[bool, Tuple[str, int]]: The result of the update operation.
    """
    user = User(pentest, body)
    user.username = user.username.lower()
    user.username = user.username.strip()
    if "password" in body:
        body["password"] = body.get("password", "").strip()
    user.domain = user.domain.lower()
    dbclient = DBClient.getInstance()
    user_existing = User.fetchObject(pentest, {"_id": ObjectId(user_iid)})
    if user_existing is None:
        return "Not found", 404
    if user_existing.username != user.username  and user_existing.domain != user.domain:
        return "Forbidden", 403
    if "type" in body:
        del body["type"]
    if "_id" in body:
        del body["_id"]
    if str(user.description) != "None" or str(user.description) != "":
        del body["description"]
    dbclient.updateInDb(pentest, "users", {"_id": ObjectId(user_iid), "type":"user"}, {"$set": body}, False, True)
    return True
