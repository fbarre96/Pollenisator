"""
Handle  request common to IPs
"""
from typing import Any, Dict, TypedDict, cast
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.ip import Ip
from pollenisator.server.servermodels.tool import delete as tool_delete
from pollenisator.server.servermodels.port import delete as port_delete
from pollenisator.server.servermodels.defect import delete as defect_delete
from pollenisator.server.modules.cheatsheet.checkinstance import delete as checkinstance_delete
from pollenisator.server.permission import permission

IpInsertResult = TypedDict('IpInsertResult', {'res': bool, 'iid': ObjectId})

@permission("pentester")
def delete(pentest: str, ip_iid: str) -> int:
    """
    Delete an IP from the database. All tools, checks, defects, and ports associated with the IP are also deleted.

    Args:
        pentest (str): The name of the pentest.
        ip_iid (str): The id of the IP to be deleted.

    Returns:
        int: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
    """
    dbclient = DBClient.getInstance()
    ip_dic = dbclient.findInDb(pentest, "ips", {"_id":ObjectId(ip_iid)}, False)
    if ip_dic is None:
        return 0
    tools = dbclient.findInDb(pentest, "tools",
                                {"ip": ip_dic["ip"]}, True)
    for tool in tools:
        tool_delete(pentest, tool["_id"])
    checks = dbclient.findInDb(pentest, "checkinstances",
                                {"target_iid": str(ip_iid)}, True)
    for check in checks:
        checkinstance_delete(pentest, check["_id"])
    defects = dbclient.findInDb(pentest, "defects",
                                    {"ip": ip_dic["ip"], "$or": [{"port": {"$exists": False}}, {"port": None}]}, True)
    for defect in defects:
        defect_delete(pentest, defect["_id"])
    ports = dbclient.findInDb(pentest, "ports",
                                {"ip": ip_dic["ip"]}, True)
    for port in ports:
        port_delete(pentest, port["_id"])
    res = dbclient.deleteFromDb(pentest, "ips", {"_id": ObjectId(ip_iid)}, False)
    if res is None:
        return 0
    else:
        return res

@permission("pentester")
def insert(pentest: str, body: Dict[str, Any]) -> IpInsertResult:
    """
    Insert a new IP into the database. If an IP with the same details already exists, the function will return the id of 
    the existing IP. Otherwise, the new IP is inserted and all IP checks are added.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the IP details.

    Returns:
        IpInsertResult: A dictionary containing the result of the operation and the id of the inserted IP.
    """
    dbclient = DBClient.getInstance()
    ip_o = Ip(pentest, body)
    base = ip_o.getDbKey()
    existing = dbclient.findInDb(pentest, "ips", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    parent = ip_o.getParentId()
    ins_result = dbclient.insertInDb(pentest, "ips", body, parent)
    iid = ins_result.inserted_id
    ip_o._id = iid
    ip_o.add_ip_checks()
    return {"res":True, "iid":iid}

@permission("pentester")
def update(pentest: str, ip_iid: str, body: Dict[str, Any]) -> bool:
    """
    Update an IP in the database. The new IP details are set in the database and all IP checks are added.

    Args:
        pentest (str): The name of the pentest.
        ip_iid (str): The id of the IP to be updated.
        body (Dict[str, Any]): A dictionary containing the new IP details.

    Returns:
        bool: True if the operation was successful.
    """
    dbclient = DBClient.getInstance()
    dbclient.updateInDb(pentest, "ips", {"_id":ObjectId(ip_iid)}, {"$set":body}, False, True)
    new = Ip.fetchObject(pentest, {"_id":ObjectId(ip_iid)})
    new = cast(Ip, new)
    new.add_ip_checks()
    return True
