"""
Handle  request common to Ports
"""
from typing import Any, Dict, TypedDict, cast
from bson import ObjectId
from pollenisator.core.models.port import Port
from pollenisator.server.permission import permission

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
    port_o = Port.fetchObject(pentest, {"_id":ObjectId(port_iid)})
    if port_o is None:
        return 0
    port_o = cast(Port, port_o)
    res = port_o.deleteFromDb()
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
    port_o = Port(pentest, body)
    return port_o.addInDb()

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
    existing_port = Port.fetchObject(pentest, {"_id":ObjectId(port_iid)})
    if existing_port is None:
        return False
    existing_port = cast(Port, existing_port)
    return existing_port.updateInDb(body)
