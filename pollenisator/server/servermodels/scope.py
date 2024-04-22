"""
Handle request common to Scopes
"""
from typing import Any, Dict, Tuple, Union, cast
from typing_extensions import TypedDict
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.scope import Scope
from pollenisator.server.permission import permission

ScopeInsertResult = TypedDict('ScopeInsertResult', {'res': bool, 'iid': ObjectId})
ErrorStatus = Tuple[str, int]

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
    scope_o = Scope.fetchObject(pentest, {"_id": ObjectId(scope_iid)})
    if scope_o is None:
        return 0
    scope_o = cast(Scope, scope_o)
    return scope_o.deleteFromDb()

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
    scope_o = Scope(pentest, body)
    return scope_o.addInDb()

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

@permission("pentester")
def getChildren(pentest: str, scope_iid: str) -> Union[Dict[str, Any], ErrorStatus]:
    """
    Get the children of a scope.

    Args:
        pentest (str): The name of the pentest.
        scope_iid (str): The id of the scope.

    Returns:
        Dict[str, Any]: A dictionary containing the children of the scope.
    """
    scope_o = Scope.fetchObject(pentest, {"_id": ObjectId(scope_iid)})
    if scope_o is None:
        return "Not found", 404
    scope_o = cast(Scope, scope_o)
    return scope_o.get_children()
