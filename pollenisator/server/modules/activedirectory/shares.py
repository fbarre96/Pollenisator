# coding: utf-8

from __future__ import absolute_import
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.server.modules.activedirectory.share_file import ShareFile
from pollenisator.server.permission import permission

class Share(ServerElement):
    coll_name = "shares"
    name = "Share"
    def __init__(self, pentest=None, valuesFromDb=None):
        if valuesFromDb is None:
            valuesFromDb = {}
        self.initialize(pentest, valuesFromDb.get("_id"),  valuesFromDb.get("ip"),
         valuesFromDb.get("share"),  valuesFromDb.get("files"), valuesFromDb.get("infos"))

    def initialize(self, pentest=None, _id=None, ip=None, share=None,  files=None, infos=None): 
        """
        :param ip: The ip of this Share. 
        :type ip: str
        :param share: The share of this Share. 
        :type share: str

        :param files: The files of this Share. 
        :type files: List[ShareFile]
        """
       
        self._id = _id
        self.ip = ip
        self.share = share
        self.files = [] 
        self.infos =  infos if infos is not None else {}
        if files is not None:
            for f in files:
                if not isinstance(f, ShareFile):
                    f = ShareFile(f)
                self.files.append(f)
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        return self

    def getData(self):
        return {"_id": self._id, "ip":self.ip, "share": self.share,  "files":[f.getData() for f in self.files], "infos":self.infos}

    def addInDb(self):
        res = insert(self.pentest, self.getData())
        self._id = ObjectId(res["iid"])
        return res

    def update(self, iid=None):
        if iid is not None:
            self._id = iid
        return update(self.pentest, self._id, self.getData())

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "share"
        ds = dbclient.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            # disabling this error as it is an abstract function
            yield cls(pentest, d)  #  pylint: disable=no-value-for-parameter
    
    @classmethod
    def fetchObject(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        pipeline["type"] = "share"
        dbclient = DBClient.getInstance()
        d = dbclient.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls(pentest, d)

    @property
    def ip(self):
        """Gets the ip of this Share.


        :return: The ip of this Share.
        :rtype: str
        """
        return self._ip

    @ip.setter
    def ip(self, ip):
        """Sets the ip of this Share.


        :param ip: The ip of this Share.
        :type ip: str
        """

        self._ip = ip

    @property
    def share(self):
        """Gets the share of this Share.


        :return: The share of this Share.
        :rtype: str
        """
        return self._share

    @share.setter
    def share(self, share):
        """Sets the share of this Share.


        :param share: The share of this Share.
        :type share: str
        """

        self._share = share

    @property
    def files(self):
        """Gets the files of this Share.


        :return: The files of this Share.
        :rtype: ShareInfos
        """
        return self._files

    @files.setter
    def files(self, files):
        """Sets the files of this Share.


        :param files: The infos of this Share.
        :type files: ShareFile
        """
        self._files = files

    def add_file(self, path, flagged, priv, size, domain, user, infos=None):
        found = False
        for f in self.files:
            if path == f.path:
                found = True
                f.add_user(domain, user, priv)
        if not found:
            share_file = ShareFile().initialize(path, flagged, size, infos=infos)
            share_file.add_user(domain, user, priv)
            self.files.append(share_file)

    @classmethod
    def getTriggers(cls):
        """
        Return the list of trigger declared here
        """
        return []

    def __str__(self):
        """
        Get a string representation of a defect.

        Returns:
            Returns the defect +title.
        """
        return self.share
    
    @classmethod
    def getSearchableTextAttribute(cls):
        return ["share", "ip"]



@permission("pentester")
def delete(pentest, share_iid): 
    """Delete Share

    Delete an Active Directory Share

    :param pentest: 
    :type pentest: str
    :param share_iid: 
    :type share_iid: str

    :rtype: Union[None, Tuple[None, int], Tuple[None, int, Dict[str, str]]
    """
    dbclient = DBClient.getInstance()
    share_dic = dbclient.findInDb(pentest, "shares", {"_id":ObjectId(share_iid), "type":"share"}, False)
    if share_dic is None:
        return 0
    res = dbclient.deleteFromDb(pentest, "shares", {"_id": ObjectId(share_iid), "type":"share"}, False)
    if res is None:
        return 0
    else:
        return res

@permission("pentester")
def insert(pentest, body): 
    """insert share

    Add an Active Directory computer

    :param pentest: pentest name
    :type pentest: str
    :param share: 
    :type share: dict | bytes

    :rtype: Union[None, Tuple[None, int], Tuple[None, int, Dict[str, str]]
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
def update(pentest, share_iid, body): 
    """Update Share

    Update an Active Directory computer

    :param pentest: 
    :type pentest: str
    :param share_iid: 
    :type share_iid: str
    :param share: 
    :type share: dict | bytes

    :rtype: Union[None, Tuple[None, int], Tuple[None, int, Dict[str, str]]
    """
    share = Share(pentest, body) 
    dbclient = DBClient.getInstance()
    existing = Share.fetchObject(pentest, {"_id": ObjectId(share_iid)})
    if existing.share != share.share  and existing.ip != share.ip:
        return "Forbidden", 403
    if "type" in body:
        del body["type"]
    if "_id" in body:
        del body["_id"]
    dbclient.updateInDb(pentest, "shares", {"_id": ObjectId(share_iid), "type":"share"}, {"$set": body}, False, True)
    return True
