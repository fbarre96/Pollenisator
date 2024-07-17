"""
Handle  request common to Waves
"""
from typing import Any, Dict, Optional, Tuple, Union, cast
from typing_extensions import TypedDict
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.wave import Wave
from pollenisator.server.modules.cheatsheet.checkinstance import  delete as checkinstance_delete
from pollenisator.server.permission import permission

ErrorStatus = Tuple[str, int]

WaveInsertResult = TypedDict('WaveInsertResult', {'res': bool, 'iid': ObjectId})

@permission("pentester")
def delete(pentest: str, wave_iid: str) -> int:
    """
    Delete a wave. The wave is fetched from the database and all tools and intervals associated with the wave are deleted 
    from the database. All check instances associated with the wave are also deleted. Finally, the wave itself is deleted 
    from the database.

    Args:
        pentest (str): The name of the pentest.
        wave_iid (str): The id of the wave to be deleted.

    Returns:
        int: The result of the deletion operation. If the wave was not found, None is returned. Otherwise, the 
        number of deleted documents is returned.
    """
    wave_o = Wave.fetchObject(pentest, {"_id": ObjectId(wave_iid)})
    if wave_o is None:
        return 0
    wave_o = cast(Wave, wave_o)
    return wave_o.deleteFromDb()

@permission("pentester")
def insert(pentest: str, body: Dict[str, Any]) -> WaveInsertResult:
    """
    Insert a new wave. A ServerWave object is created from the body. The wave is checked for uniqueness in the database. 
    If the wave already exists, a dictionary with the result as False and the id of the existing wave is returned. If the 
    wave does not exist, it is inserted into the database and the id of the inserted wave is returned in a dictionary with 
    the result as True.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the data for the wave.

    Returns:
        WaveInsertResult: A dictionary containing the result of the operation and the id of the wave.
    """
    wave_o = Wave(pentest, body)
    return wave_o.addInDb()

@permission("pentester")
def update(pentest: str, wave_iid: ObjectId, body: Dict[str, Any]) -> None:
    """
    Update a wave. The wave is fetched from the database and its commands are stored. The commands for the wave are 
    updated with the commands from the body. The wave is then updated in the database.

    Args:
        pentest (str): The name of the pentest.
        wave_iid (ObjectId): The id of the wave to be updated.
        body (Dict[str, Any]): A dictionary containing the new data for the wave.
    """
    dbclient = DBClient.getInstance()
    wave = Wave(pentest, body)
    dbclient.updateInDb(pentest, "waves", {"_id":ObjectId(wave_iid)}, {"$set":wave.getData()}, False, True)

def addUserCommandsToWave(pentest: str, wave_iid: ObjectId, user: str) -> bool:
    """
    Add user commands to a wave. The commands owned by the user are fetched from the database and added to the wave. The 
    wave is then updated in the database.

    Args:
        pentest (str): The name of the pentest.
        wave_iid (ObjectId): The id of the wave to which the commands will be added.
        user (str): The user whose commands will be added to the wave.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    dbclient = DBClient.getInstance()
    mycommands = dbclient.findInDb(pentest, "commands", {"owners":user}, True)
    comms = [command["_id"] for command in mycommands]
    wave = dbclient.findInDb(pentest, "waves", {"_id":ObjectId(wave_iid)}, False)
    if wave is None:
        return False
    wave["wave_commands"] += comms
    update(pentest, wave_iid, {"wave_commands": wave["wave_commands"]})
    return True

@permission("pentester")
def getChecksData(pentest: str, wave_iid: str) -> Union[Dict[str, Any], ErrorStatus]:
    """
    Get the command suggestions for the Wave.

    Returns:
        Union[Dict[str, Any], ErrorStatus]: A dictionary containing the command suggestions or an error status.
    """
    wave_o = Wave.fetchObject(pentest, {"_id": ObjectId(wave_iid)})
    if wave_o is None:
        return "Not found", 404
    wave_o = cast(Wave, wave_o)
    return wave_o.getChecksData()