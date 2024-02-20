"""
Handle request common to Scopes
"""
from typing import Any, Dict
from typing_extensions import TypedDict
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.scope import Scope
from pollenisator.server.modules.cheatsheet.checkinstance import delete as checkinstance_delete
from pollenisator.server.permission import permission

ScopeInsertResult = TypedDict('ScopeInsertResult', {'res': bool, 'iid': str})

@permission("pentester")
def delete(pentest: str, scope_iid: str) -> int:
    """
    Delete a scope from the database. All checks associated with the scope are also deleted. The scope is removed from all 
    IPs that it fits. If the scope is part of a wave, a notification is sent to update the wave.

    Args:
        pentest (str): The name of the pentest.
        scope_iid (str): The id of the scope to be deleted.

    Returns:
       int: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
    """
    dbclient = DBClient.getInstance()
    # deleting checks with scope 
    scope_o = Scope(pentest, dbclient.findInDb(pentest, "scopes", {"_id": ObjectId(scope_iid)}, False))
    checks = dbclient.findInDb(pentest, "checkinstances", {"target_iid": ObjectId(scope_iid), "target_type": "scope"})
    for check in checks:
        checkinstance_delete(pentest, check["_id"])
    # Deleting this scope against every ips
    ips = Ip.getIpsInScope(pentest, ObjectId(scope_iid))
    for ip in ips:
        ip.removeScopeFitting(pentest, ObjectId(scope_iid))
    res = dbclient.deleteFromDb(pentest, "scopes", {"_id": ObjectId(scope_iid)}, False)
    parent_wave = dbclient.findInDb(pentest, "waves", {"wave": scope_o.wave}, False)
    if parent_wave is None:
        return
    dbclient.send_notify(pentest,
                            "waves", parent_wave["_id"], "update", "")
    # Finally delete the selected element
    if res is None:
        return 0
    else:
        return res

@permission("pentester")
def insert(pentest: str, body: Dict[str, Any]) -> ScopeInsertResult:
    """
    Inserts a new scope into the database.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the data of the scope to be inserted.

    Returns:
        Dict[str, Union[bool, str]]: A dictionary containing the result of the operation and the id of the inserted scope.
    """
    dbclient = DBClient.getInstance()
    scope_o = Scope(pentest, body)
    # Checking unicity
    base = scope_o.getDbKey()
    existing = dbclient.findInDb(pentest, "scopes", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    # Inserting scope
    parent = scope_o.getParentId()
    res_insert = dbclient.insertInDb(pentest, "scopes", base, parent, notify=True)
    ret = res_insert.inserted_id
    scope_o._id = ret
    # adding the appropriate checks for this scope.
    scope_o.add_scope_checks()
    _updateIpsScopes(pentest, scope_o)
    return {"res":True, "iid":ret}


def _updateIpsScopes(pentest: str, scope_o: 'Scope') -> None:
    """
    Update the scopes of all IPs in the database. If an IP fits in the given scope and the scope is not already in the IP's 
    scopes, the scope is added to the IP's scopes.

    Args:
        pentest (str): The name of the pentest.
        scope_o ('Scope'): The scope object to be tested against all IPs.
    """
    # Testing this scope against every ips
    dbclient = DBClient.getInstance()
    ips = dbclient.findInDb(pentest, "ips", {})
    for ip in ips:
        ip_o = Ip(pentest, ip)
        if scope_o._id not in ip_o.in_scopes:
            if ip_o.fitInScope(scope_o.scope):
                ip_o.addScopeFitting(pentest, scope_o.getId())

@permission("pentester")
def update(pentest: str, scope_iid: str, body: Dict[str, Any]) -> bool:
    """
    Update a scope in the database. The new scope details are set in the database and all scope checks are added. The scope 
    is also added to all IPs that it fits.

    Args:
        pentest (str): The name of the pentest.
        scope_iid (str): The id of the scope to be updated.
        body (Dict[str, Any]): A dictionary containing the new scope details.

    Returns:
        bool: True if the operation was successful.
    """
    dbclient = DBClient.getInstance()
    dbclient.updateInDb(pentest, "scopes", {"_id":ObjectId(scope_iid)}, {"$set":body}, False, True)
    return True
