"""
Handle  request common to IPs
"""
from typing import Any, Dict, Tuple, TypedDict, Union, cast
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.ip import Ip
from pollenisator.server.permission import permission

IpInsertResult = TypedDict('IpInsertResult', {'res': bool, 'iid': ObjectId})
ErrorStatus = Tuple[str, int]

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
    ip_o = Ip.fetchObject(pentest, {"_id": ObjectId(ip_iid)})
    if ip_o is None:
        return 0
    ip_o = cast(Ip, ip_o)
    return ip_o.deleteFromDb()

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
    ip_o = Ip(pentest, body)
    return ip_o.addInDb()

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
    new = Ip.fetchObject(pentest, {"_id":ObjectId(ip_iid)})
    new = cast(Ip, new)
    new.updateInDb(body)
    return True

@permission("pentester")
def getHostData(pentest: str, ip_iid: str) -> Union[Dict[str, Any], ErrorStatus]:
    """
    Get dictionary containing the useful data for a host

    Returns:
        Union[Dict[str, Any], ErrorStatus]: A dictionary containing the useful data for a host
    """
    ip_o = Ip.fetchObject(pentest, {"_id": ObjectId(ip_iid)})
    if ip_o is None:
        return "Not found", 404
    ip_o = cast(Ip, ip_o)
    return ip_o.getHostData()
