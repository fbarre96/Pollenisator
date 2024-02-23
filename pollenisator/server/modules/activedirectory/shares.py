"""Module to manage shares in the database."""
# coding: utf-8

from __future__ import absolute_import
from typing import Dict, Iterator, List, Optional, Any, Tuple, Union
from typing_extensions import TypedDict
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.element import Element
from pollenisator.server.modules.activedirectory.share_file import ShareFile
from pollenisator.server.permission import permission

ShareInsertResult = TypedDict('ShareInsertResult', {'res': bool, 'iid': ObjectId})

class Share(Element):
    """
    Share class, a smb share in a network
    
    Attributes:
        coll_name: collection name in database
    """

    coll_name = "shares"

    def __init__(self, pentest=None, valuesFromDb=None):
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest ,valuesFromDb)
        self.initialize(valuesFromDb.get("ip", ""),
         valuesFromDb.get("share", ""),  valuesFromDb.get("files"), valuesFromDb.get("infos"))

    def initialize(self, ip: str, share: str, files: Optional[List[ShareFile]] = None, infos: Optional[Dict[str, Any]] = None) -> 'Share':
        """
        Initialize a Share object with the provided values. If a value is not provided, the corresponding attribute is 
        initialized with a default value.

        Args:
            ip (Optional[str], optional): The IP address of the Share. Defaults to None.
            share (Optional[str], optional): The share of the Share. Defaults to None.
            files (Optional[List[ShareFile]], optional): The files of the Share. Defaults to None.
            infos (Optional[Dict[str, Any]], optional): Additional information about the Share. Defaults to None.

        Returns:
            Share: The initialized Share object.
        """

        self.ip = ip
        self.share = share
        self.files = []
        self.infos =  infos if infos is not None else {}
        if files is not None:
            for f in files:
                if not isinstance(f, ShareFile):
                    f = ShareFile(self.pentest, f)
                self.files.append(f)
        return self

    def getData(self) -> Dict[str, Any]:
        """
        Get the data of this Share object. The data includes the id, IP address, share, files, and additional information.

        Returns:
            Dict[str, Any]: The data of this Share object.
        """
        return {"_id": self._id, "ip":self.ip, "share": self.share,  "files":[f.getData() for f in self.files], "infos":self.infos}

    def addInDb(self) -> ShareInsertResult:
        """
        Add this Share object to the database. The data of the object is fetched using the getData method and inserted into 
        the database. The id of the inserted object is stored in the _id attribute of this object.

        Returns:
            ShareInsertResult: The result of the insert operation.
        """
        res: ShareInsertResult = insert(self.pentest, self.getData())
        self._id = ObjectId(res["iid"])
        return res

    def update(self, iid: Optional[ObjectId] = None) -> Union[bool, Tuple[str, int]]:
        """
        Update this Share object in the database. If an id is provided, it is used as the id of the object to be updated. 
        Otherwise, the id of this object is used. The data of the object is fetched using the getData method and updated in 
        the database.

        Args:
            iid (Optional[ObjectId], optional): The id of the object to be updated. Defaults to None.

        Returns:
            Union[bool, Tuple[str, int]]: The result of the update operation.
        """
        if iid is not None:
            self._id = iid
        res: Union[bool, Tuple[str, int]] = update(self.pentest, self._id, self.getData())
        return res

    @classmethod
    def fetchObjects(cls, pentest: str, pipeline: Dict[str, Any]) -> Optional[Iterator['Share']]:
        """
        Fetch many shares from the database and return a Cursor to iterate over Share objects.

        Args:
            pentest (str): The name of the current pentest.
            pipeline (Dict[str, Any]): A MongoDB search pipeline.

        Returns:
            Optional[Iterator[Share]]: A cursor to iterate over Share objects, or None if no shares are found.
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "share"
        ds = dbclient.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            yield Share(pentest, d)

    @classmethod
    def fetchObject(cls, pentest: str, pipeline: Dict[str, Any]) -> Optional['Share']:
        """
        Fetch a share from the database and return a Share object. If no share is found, None is returned.

        Args:
            pentest (str): The name of the current pentest.
            pipeline (Dict[str, Any]): A MongoDB search pipeline.

        Returns:
            Optional[Share]: A Share object, or None if no share is found.
        """
        pipeline["type"] = "share"
        dbclient = DBClient.getInstance()
        d = dbclient.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return Share(pentest, d)

    def deleteFromDb(self) -> int:
        """
        Delete this Share object from the database.

        Returns:
            int: The result of the delete operation.
        """
        dbclient = DBClient.getInstance()
        res = dbclient.deleteFromDb(self.pentest, "shares", {"_id": ObjectId(self.getId()), "type":"share"}, False)
        if res is None:
            return 0
        else:
            return res

    @property
    def ip(self) -> str:
        """
        Get the IP address of this Share object.

        Returns:
            str: The IP address of this Share object.
        """
        return self._ip

    @ip.setter
    def ip(self, ip: str) -> None:
        """
        Set the IP address of this Share object.

        Args:
            ip (str): The new IP address of this Share object.
        """
        self._ip = ip

    @property
    def share(self) -> str:
        """Gets the share of this Share.

        Returns:
            str: The share of this Share
        """
        return self._share

    @share.setter
    def share(self, share: str) -> None:
        """Sets the share of this Share.

        Args:
            share (str): The share of this Share
        """

        self._share = share

    @property
    def files(self) -> List[ShareFile]:
        """
        Get the files of this Share object.

        Returns:
            List[ShareFile]: The files of this Share object.
        """
        return self._files

    @files.setter
    def files(self, files: List[ShareFile]) -> None:
        """Sets the files of this Share.

        Args:
            files (List[ShareFile]): The files of this Share object.
        """
        self._files = files

    def add_file(self, path: str, flagged: bool, priv: str, size: int, domain: str, user: str, infos: Optional[Dict[str, Any]] = None) -> None:
        """
        Add a file to this Share object. If the file already exists, the user is added to the file. Otherwise, a new ShareFile 
        object is created and added to the files of this Share object.

        Args:
            path (str): The path of the file.
            flagged (bool): Whether the file is flagged.
            priv (str): The privileges of the user on the file.
            size (int): The size of the file.
            domain (str): The domain of the user.
            user (str): The name of the user.
            infos (Optional[Dict[str, Any]], optional): Additional information about the file. Defaults to None.
        """
        found = False
        for f in self.files:
            if path == f.path:
                found = True
                f.add_user(domain, user, priv)
        if not found:
            share_file = ShareFile(self.pentest).initialize(path, flagged, size, infos=infos)
            share_file.add_user(domain, user, priv)
            self.files.append(share_file)

    @classmethod
    def getTriggers(cls) -> List[str]:
        """
        Return the list of trigger declared here

        Returns:
            List[str]: The list of triggers.
        """
        return []

    def __str__(self) -> str:
        """
        Get a string representation of a share.

        Returns:
            str: Returns the share
        """
        return self.share

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Returns a list of attribute names that can be used for searching.

        Returns:
            List[str]: A list containing the attribute names that can be used for searching. In this case, it's ["share"].
        """
        return ["share", "ip"]



@permission("pentester")
def delete(pentest: str, share_iid: str) -> int:
    """
    Delete an Active Directory Share. If the share does not exist in the database, 0 is returned. Otherwise, the share is 
    deleted from the database and the result of the delete operation is returned.

    Args:
        pentest (str): The name of the current pentest.
        share_iid (str): The id of the share to be deleted.

    Returns:
        int: The result of the delete operation.
    """
    share_o = Share.fetchObject(pentest, {"_id": ObjectId(share_iid)})
    if share_o is None:
        return 0
    return share_o.deleteFromDb()
    

@permission("pentester")
def insert(pentest: str, body: Dict[str, Any]) -> ShareInsertResult:
    """
    Insert a share into the database. The share is represented as a dictionary or bytes. If the share already exists in 
    the database, a dictionary containing the result of the operation and the id of the existing share is returned. 
    Otherwise, the share is inserted into the database and a dictionary containing the result of the operation and the id 
    of the inserted share is returned.

    Args:
        pentest (str): The name of the current pentest.
        body (Union[dict, bytes]): The share to be inserted.

    Returns:
        ShareInsertResult: The result of the insert operation.
    """
    share = Share(pentest, body)
    dbclient = DBClient.getInstance()
    existing = dbclient.findInDb(pentest, 
        "shares", {"type":"share", "share":share.share, "ip":share.ip}, False)
    if existing is not None:
        return {"res": False, "iid": existing["_id"]}
    if "_id" in body:
        del body["_id"]
    body["type"] = "share"
    ins_result = dbclient.insertInDb(pentest,
        "shares", body, True)
    iid = ins_result.inserted_id
    return {"res": True, "iid": iid}

@permission("pentester")
def update(pentest: str, share_iid: str, body: Dict[str, Any]) -> Union[bool, Tuple[str, int]]:
    """
    Update a share in the database. The share is represented as a dictionary or bytes. If the share does not exist in 
    the database, a tuple containing the string "Forbidden" and the status code 403 is returned. Otherwise, the share is 
    updated in the database and True is returned.

    Args:
        pentest (str): The name of the current pentest.
        share_iid (str): The id of the share to be updated.
        body (Dict[str, Any]): The updated share.

    Returns:
        Union[bool, Tuple[str, int]]: The result of the update operation.
    """
    share = Share(pentest, body)
    dbclient = DBClient.getInstance()
    existing = Share.fetchObject(pentest, {"_id": ObjectId(share_iid)})
    if existing is None:
        return "Not found", 404
    if existing.share != share.share  and existing.ip != share.ip:
        return "Forbidden", 403
    if "type" in body:
        del body["type"]
    if "_id" in body:
        del body["_id"]
    dbclient.updateInDb(pentest, "shares", {"_id": ObjectId(share_iid), "type":"share"}, {"$set": body}, False, True)
    return True
