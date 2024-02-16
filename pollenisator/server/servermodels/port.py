"""
Handle  request common to Ports
"""
from typing import Any, Dict, TypedDict
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.port import Port
from pollenisator.server.servermodels.tool import delete as tool_delete
from pollenisator.server.servermodels.defect import delete as defect_delete
from pollenisator.server.modules.cheatsheet.checkinstance import delete as checkinstance_delete
from pollenisator.server.permission import permission
from pollenisator.server.modules.activedirectory.computers import Computer, insert as computer_insert

PortInsertResult = TypedDict('PortInsertResult', {'res': bool, 'iid': ObjectId})

@permission("pentester")
def delete(pentest: str, port_iid: str) -> int:
    """
    Delete a port from the database. All tools, checks, and defects associated with the port are also deleted.

    Args:
        pentest (str): The name of the pentest.
        port_iid (str): The id of the port to be deleted.

    Returns:
        int: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
    """
    dbclient = DBClient.getInstance()

    port_o = Port(pentest, dbclient.findInDb(pentest, "ports", {"_id":ObjectId(port_iid)}, False))
    tools = dbclient.findInDb(pentest, "tools", {"port": port_o.port, "proto": port_o.proto,
                                             "ip": port_o.ip}, True)
    for tool in tools:
        tool_delete(pentest, tool["_id"])
    checks = dbclient.findInDb(pentest, "checkinstances",
                                {"target_iid": str(port_iid)}, True)
    for check in checks:
        checkinstance_delete(pentest, check["_id"])
    defects = dbclient.findInDb(pentest, "defects", {"port": port_o.port, "proto": port_o.proto,
                                                "ip": port_o.ip}, True)
    for defect in defects:
        defect_delete(pentest, defect["_id"])
    res = dbclient.deleteFromDb(pentest, "ports", {"_id": ObjectId(port_iid)}, False)
    if res is None:
        return 0
    else:
        return res

@permission("pentester")
def insert(pentest: str, body: Dict[str, Any]) -> PortInsertResult:
    """
    Inserts a new port into the database.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the data of the port to be inserted.

    Returns:
        PortInsertResult: A dictionary containing the result of the operation and the id of the inserted port.
    """
    dbclient = DBClient.getInstance()
    port_o = Port(pentest, body)
    base = port_o.getDbKey()
    existing = dbclient.findInDb(pentest,
            "ports", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    parent = port_o.getParentId()
    ins_result = dbclient.insertInDb(pentest, "ports", body, parent)
    iid = ins_result.inserted_id
    port_o._id = iid
    if int(port_o.port) == 445:
        computer_insert(pentest, {"name":"", "ip":port_o.ip, "domain":"", "admins":[], "users":[], "infos":{"is_dc":False}})
    if int(port_o.port) == 88:
        res = computer_insert(pentest, {"name":"", "ip":port_o.ip, "domain":"", "admins":[], "users":[], "infos":{"is_dc":True}})
        if not res["res"]:
            comp = Computer.fetchObject(pentest, {"_id":ObjectId(res["iid"])})
            comp.infos.is_dc = True
            comp.update()
    if int(port_o.port) == 1433 or (port_o.service == "ms-sql"):
        res = computer_insert(pentest, {"name":"", "ip":port_o.ip, "domain":"", "admins":[], "users":[], "infos":{"is_sqlserver":True}})
        if not res["res"]:
            comp = Computer.fetchObject(pentest, {"_id":ObjectId(res["iid"])})
            comp.infos.is_sqlserver = True
            comp.update()
    port_o.add_port_checks()
    return {"res":True, "iid":iid}

@permission("pentester")
def update(pentest: str, port_iid: str, body: Dict[str, Any]) -> bool:
    """
    Update a port in the database. The new port details are set in the database and all port checks are added. If the 
    service of the port has changed, all tools and checks associated with the old service are deleted and new checks are 
    added for the new service.

    Args:
        pentest (str): The name of the pentest.
        port_iid (str): The id of the port to be updated.
        body (Dict[str, Any]): A dictionary containing the new port details.

    Returns:
        bool: True if the operation was successful.
    """
    dbclient = DBClient.getInstance()
    oldPort_data = dbclient.findInDb(pentest, "ports", {"_id": ObjectId(port_iid)}, False)
    if oldPort_data is None:
        return
    oldPort = Port(pentest, oldPort_data)
    dbclient.updateInDb(pentest, "ports", {"_id":ObjectId(port_iid)}, {"$set":body}, False, True)
    port_o = Port(pentest, dbclient.findInDb(pentest, "ports", {"_id": ObjectId(port_iid)}, False))
    oldService = oldPort.service
    if oldService != port_o.service:
        dbclient.deleteFromDb(pentest, "tools", {
                                "lvl": "port:onServiceUpdate", "ip": oldPort.ip, "port": oldPort.port, "proto": oldPort.proto, "status":{"$ne":"done"}}, many=True)
        dbclient.deleteFromDb(pentest, "checkinstances", {
                                "lvl": "port:onServiceUpdate", "ip": oldPort.ip, "port": oldPort.port, "proto": oldPort.proto, "status":{"$ne":"done"}}, many=True)     
        port_o.add_port_checks()
    return True
