"""
Active directory mdule to handle sharefiles
"""
# coding: utf-8

from __future__ import absolute_import
from typing import List, Optional, Dict, Any, Tuple, cast

from pollenisator.core.models.element import Element

UserTuple = Tuple[str, str, str]

class ShareFile(Element):
    """
    Class to describe file inside of shares

    Attributes:
        coll_name: collection name in database
    """
    coll_name = "sharefiles"

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize a ShareFile object. If valuesFromDb is provided, the object is initialized with these values. Otherwise, 
        it is initialized with default values.

        Args:
            pentest (str): The name of the current pentest.
            valuesFromDb (Optional[Dict[str, Any]], optional): The values with which to initialize the object. Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.users: List[UserTuple] = []
        self.initialize(valuesFromDb.get("path"), valuesFromDb.get("flagged"), valuesFromDb.get("size") , valuesFromDb.get("users"), valuesFromDb.get("infos") )

    def initialize(self, path: Optional[str]=None, flagged: Optional[bool] = None, size: Optional[int]=None,  users: Optional[List[UserTuple]]=None, infos: Optional[Dict[str, Any]]=None) -> 'ShareFile':
        """
        Initialize a ShareFile object with the provided values. If a value is not provided, the corresponding attribute is 
        initialized with a default value.

        Args:
            path (Optional[str], optional): The path of the ShareFile. Defaults to None.
            flagged (Optional[bool], optional): Whether the ShareFile is flagged. Defaults to None.
            size (Optional[int], optional): The size of the ShareFile. Defaults to None.
            users (Optional[List[UserTuple]], optional): The users of the ShareFile. Defaults to None.
            infos (Optional[Dict[str, Any]], optional): Additional information about the ShareFile. Defaults to None.

        Returns:
            ShareFile: The initialized ShareFile object.
        """
        self.path = path
        self.flagged = flagged
        self.size = size
        self.users = users if users is not None else []
        self.infos =  infos if infos is not None else {}
        return self

    def getData(self) -> Dict[str, Any]:
        """
        Get the data of this ShareFile object. The data includes the path, flagged status, size, users, and additional 
        information.

        Returns:
            Dict[str, Any]: The data of this ShareFile object.
        """
        return {"flagged": self.flagged, "path":self.path, "size":self.size,
                 "users":self.users, "infos":self.infos}

    def add_user(self, domain: str, user: str, priv: str) -> None:
        """
        Add a user to this ShareFile object. The user is represented as a tuple of domain, username, and privilege. If the 
        user already exists, it is not added again.

        Args:
            domain (str): The domain of the user.
            user (str): The username of the user.
            priv (str): The privilege of the user.
        """
        users = set(self.users)
        users.add(cast(UserTuple, (domain, user, priv)))
        self.users = list(users)

    @classmethod
    def getTriggers(cls) -> List[str]:
        """
        Return the list of trigger declared here

        Returns:
            List[str]: A list of triggers.
        """
        return []

    def __str__(self) -> str:
        """
        Get a string representation of a defect.

        Returns:
            str: Returns the defect +title.
        """
        return str(self.path) if self.path is None else ""

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Return the list of searchable text attribute

        Returns:
            List[str]: a list of searchable text attributes
        """
        return ["path"]
