"""Interval Model. Useful to limit in a time frame some tools"""

from typing import Any, Dict, Optional, cast

from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.element import Element
from pollenisator.core.models.tool import Tool
import pollenisator.core.components.utils as utils
from datetime import datetime

from pollenisator.core.models.wave import Wave


class Interval(Element):
    """
    Represents an interval object that defines an time interval where a wave can be executed.

    Attributes:
        coll_name: collection name in pollenisator database
    """
    coll_name = "intervals"

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Constructor for the Interval class.

        Args:
            pentest (str): The name of the pentest.
            valuesFromDb (Optional[Dict[str, Any]], optional): A dictionary holding values to load into the object. 
            A mongo fetched interval is optimal. Possible keys with default values are : _id (None), parent (None), 
            infos({}), wave(""), dated("None"), datef("None"). Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.initialize(valuesFromDb.get("wave", ""), valuesFromDb.get("dated", "None"),
                        valuesFromDb.get("datef", "None"), valuesFromDb.get("infos", {}))

    def initialize(self, wave: str, dated: str = "None", datef: str = "None", infos: Optional[Dict[str, Any]] = None) -> 'Interval':
        """
        Set values of interval.

        Args:
            wave (str): The parent wave name.
            dated (str, optional): A starting date and time for this interval in format : '%d/%m/%Y %H:%M:%S'. 
            Or the string "None". Defaults to "None".
            datef (str, optional): An ending date and time for this interval in format : '%d/%m/%Y %H:%M:%S'. 
            Or the string "None". Defaults to "None".
            infos (Optional[Dict[str, Any]], optional): A dictionary with key values as additional information. 
            Defaults to None.

        Returns:
            Interval: This object.
        """
        self.wave = wave
        self.dated = dated
        self.datef = datef
        self.infos = infos if infos is not None else {}
        return self

    def __str__(self) -> str:
        """
        Get a string representation of a command group.

        Returns:
            str: Returns the string "Interval".
        """
        return "Interval"

    @classmethod
    def _translateDateString(cls, datestring: str) -> Optional[datetime]:
        """
        Returns the datetime object when given a str with format '%d/%m/%Y %H:%M:%S'

        Args:
            datestring (str): A string formatted as datetime format : '%d/%m/%Y %H:%M:%S'

        Returns:
            Optional[datetime]: A datetime object if the string is valid, None otherwise.
        """
        ret = None
        if isinstance(datestring, str):
            if datestring != "None":
                ret = datetime.strptime(
                    datestring, '%d/%m/%Y %H:%M:%S')
        return ret

    def getEndingDate(self) -> Optional[datetime]:
        """
        Returns the ending date and time of this interval.

        Returns:
            Optional[datetime]: A datetime object representing the ending date and time of this interval, 
            or None if the date is not set.
        """
        return Interval._translateDateString(self.datef)

    def getDbKey(self) -> Dict[str, str]:
        """
        Returns a dictionary from model to use as unique composed key.

        Returns:
            Dict[str, str]: A dictionary with one key: "wave".
        """
        return {"wave": self.wave}

    def setToolsInTime(self) -> None:
        """
        Get all Out of Time (OOT) tools in this wave and checks if this Interval makes them in time. 
        If it is the case, set them in time.
        """
        if utils.fitNowTime(self.dated, self.datef):
            tools = Tool.fetchObjects(self.pentest, {"wave": self.wave, "status": "OOT"})
            if tools is None:
                return
            for tool in tools:
                tool = cast(Tool, tool)
                tool.setInTime()

    def getParentId(self) -> Optional[ObjectId]:
        """
        Returns the MongoDB ObjectId _id of the first parent of this object. For an interval, it is the wave.

        Returns:
            Optional[str]: The parent wave's ObjectId _id, or None if not found.
        """
        dbclient = DBClient.getInstance()
        res = dbclient.findInDb(self.pentest, "waves", {"wave": self.wave}, False)
        if res:
            return ObjectId(res.get("_id", None)) if res.get("_id", None) is not None else None
        return None

    def deleteFromDb(self) -> int:
        """
        Deletes this interval from the database.

        Returns:
            int: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
        """
        dbclient = DBClient.getInstance()
        res = dbclient.deleteFromDb(self.pentest, "intervals", {"_id": ObjectId(self.getId())}, False)
        parent_wave = Wave.fetchObject(self.pentest, {"wave": self.wave})
        if parent_wave is not None:
            dbclient.send_notify(self.pentest,
                                    "waves", str(parent_wave.getId()), "update", "")
            other_intervals = Wave.fetchObjects(self.pentest, {"wave": self.wave})
            if other_intervals is not None:
                no_interval_in_time = True
                for other_interval_o in other_intervals:
                    other_interval_o = cast(Interval, other_interval_o)
                    if utils.fitNowTime(other_interval_o.dated, other_interval_o.datef):
                        no_interval_in_time = False
                        break
                if no_interval_in_time:
                    tools = Tool.fetchObjects(self.pentest, {"wave": self.wave})
                    if tools is not None:
                        for tool_o in tools:
                            tool_o = cast(Tool, tool_o)
                            tool_o.setOutOfTime()
        if res is None:
            return 0
        else:
            return res
