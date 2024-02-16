"""
Handle  request common to intervals
"""
from typing import Any, Dict, TypedDict, Union, Tuple, cast
from bson import ObjectId
from pymongo.results import InsertOneResult
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.interval import Interval
from pollenisator.core.models.tool import Tool
from pollenisator.core.components.utils import fitNowTime, stringToDate
from pollenisator.server.permission import permission

IntervalInsertResult = TypedDict('IntervalInsertResult', {'res': bool, 'iid': ObjectId})

@permission("pentester")
def delete(pentest: str, interval_iid: str) -> Union[Tuple[str, int], int]:
    """
    Delete an interval from the database. If the interval is part of a wave and there are no other intervals in the wave 
    that fit the current time, all tools in the wave are marked as out of time.

    Args:
        pentest (str): The name of the pentest.
        interval_iid (str): The id of the interval to be deleted.

    Returns:
        int: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
    """
    dbclient = DBClient.getInstance()
    interval_o = Interval(pentest, dbclient.findInDb(pentest, "intervals", {"_id": ObjectId(interval_iid)}, False))
    if interval_o is None:
        return "Interval not found", 404
    res = dbclient.deleteFromDb(pentest, "intervals", {"_id": ObjectId(interval_iid)}, False)
    parent_wave = dbclient.findInDb(pentest, "waves", {"wave": interval_o.wave}, False)
    if parent_wave is not None:
        dbclient.send_notify(pentest,
                                "waves", parent_wave["_id"], "update", "")
        other_intervals = dbclient.findInDb(pentest, "waves", {"wave": interval_o.wave})
        no_interval_in_time = True
        for other_interval_data in other_intervals:
            other_interval = Interval(pentest, other_interval_data)
            if fitNowTime(other_interval.dated, other_interval.datef):
                no_interval_in_time = False
                break
        if no_interval_in_time:
            tools = dbclient.findInDb(pentest, "tools", {"wave": interval_o.wave})
            for tool_data in tools:
                tool = Tool(pentest, tool_data)
                tool.setOutOfTime(pentest)
    if res is None:
        return 0
    else:
        return res

@permission("pentester")
def insert(pentest: str, body: Dict[str, Any]) -> Union[IntervalInsertResult, Tuple[str, int]]:
    """
    Insert a new interval into the database. The interval is also added to its parent wave. If the start and end dates of 
    the interval are valid, all tools in the wave are checked to see if they fit within the new interval.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the interval details.

    Returns:
        Union[IntervalInsertResult, Tuple[str, int]]: A dictionary containing the result of the operation and 
        the id of the inserted interval, or a tuple containing an error message and status code if the dates are not valid.
    """
    dbclient = DBClient.getInstance()
    if "_id" in body:
        del body["_id"]
    interval_o = Interval(pentest, body)
    parent = interval_o.getParentId()
    try:
        stringToDate(body.get("dated", ""))
        stringToDate(body.get("datef", ""))
    except ValueError as _e:
        return "Invalid date format, expected '%d/%m/%Y %H:%M:%S'", 400
    ins_result = dbclient.insertInDb(pentest, "intervals", body, str(parent), multi=False)
    ins_result = cast(InsertOneResult, ins_result)
    interval_o.setToolsInTime()
    iid = ins_result.inserted_id
    return {"res":True, "iid":iid}

@permission("pentester")
def update(pentest: str, interval_iid: str, body: Dict[str, Any]) -> bool:
    """
    Update an interval in the database. The start and end dates of the interval are checked and all tools in the parent 
    wave are marked as in or out of time accordingly.

    Args:
        pentest (str): The name of the pentest.
        interval_iid (str): The id of the interval to be updated.
        body (Dict[str, Any]): A dictionary containing the new interval details.

    Returns:
        bool: True if the operation was successful.
    """
    dbclient = DBClient.getInstance()
    interval_o = Interval(pentest, dbclient.findInDb(pentest, "intervals", {"_id": ObjectId(interval_iid)}, False))
    interval_o.setToolsInTime()
    dbclient.updateInDb(pentest, "intervals", {"_id":ObjectId(interval_iid)}, {"$set":body}, False, True)
    return True
