"""Interval Model. Useful to limit in a time frame some tools"""

from pollenisator.core.Models.Element import Element
from pollenisator.core.Models.Tool import Tool
import pollenisator.core.Components.Utils as Utils
from bson.objectid import ObjectId
from datetime import datetime


class Interval(Element):
    """
    Represents an interval object that defines an time interval where a wave can be executed.

    Attributes:
        coll_name: collection name in pollenisator database
    """
    coll_name = "intervals"

    def __init__(self, valuesFromDb=None):
        """Constructor
        Args:
            valueFromDb: a dict holding values to load into the object. A mongo fetched interval is optimal.
                        possible keys with default values are : _id (None), parent (None), tags([]), infos({}),
                        wave(""), dated("None"), datef("None")
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(valuesFromDb.get("_id", None), valuesFromDb.get("parent", None),  valuesFromDb.get(
            "tags", []), valuesFromDb.get("infos", {}))
        self.initialize(valuesFromDb.get("wave", ""), valuesFromDb.get("dated", "None"),
                        valuesFromDb.get("datef", "None"), valuesFromDb.get("infos", {}))

    def initialize(self, wave, dated="None", datef="None", infos=None):
        """Set values of interval
        Args:
            wave: the parent wave name
            dated: a starting date and tiem for this interval in format : '%d/%m/%Y %H:%M:%S'. or the string "None"
            datef: an ending date and tiem for this interval in format : '%d/%m/%Y %H:%M:%S'. or the string "None"
            infos: a dictionnary with key values as additional information. Default to None
        Returns:
            this object
        """
        self.wave = wave
        self.dated = dated
        self.datef = datef
        self.infos = infos if infos is not None else {}
        return self

 

    def __str__(self):
        """
        Get a string representation of a command group.

        Returns:
            Returns the string "Interval".
        """
        return "Interval"

    @classmethod
    def _translateDateString(cls, datestring):
        """Returns the datetime object when given a str wih format '%d/%m/%Y %H:%M:%S'
        Args:
            a string formated as datetime format : '%d/%m/%Y %H:%M:%S'
        """
        ret = None
        if type(datestring) == str:
            if datestring != "None":
                ret = datetime.strptime(
                    datestring, '%d/%m/%Y %H:%M:%S')
        return ret

    def getEndingDate(self):
        """Returns the ending date and time of this interval
        Returns:
            a datetime object.
        """
        return Interval._translateDateString(self.datef)

    def getDbKey(self):
        """Return a dict from model to use as unique composed key.
        Returns:
            A dict (1 key :"wave")
        """
        return {"wave": self.wave}
