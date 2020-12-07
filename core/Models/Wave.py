"""Wave Model. Stores which command should be launched and associates Interval and Scope"""

from bson.objectid import ObjectId
from core.Models.Tool import Tool
from core.Models.Element import Element
from core.Models.Ip import Ip
from core.Models.Interval import Interval
import core.Components.Utils as Utils
from core.Models.Scope import Scope


class Wave(Element):
    """
    Represents a Wave object. A wave is a series of tools to execute.

    Attributes:
        coll_name: collection name in pollenisator database
    """
    coll_name = "waves"

    def __init__(self, valuesFromDb=None):
        """Constructor
        Args:
            valueFromDb: a dict holding values to load into the object. A mongo fetched interval is optimal.
                        possible keys with default values are : _id(None), parent(None), tags([]), infos({}),
                        wave(""), wave_commands([])
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(valuesFromDb.get("_id", None), valuesFromDb.get("parent", None), valuesFromDb.get(
            "tags", []), valuesFromDb.get("infos", {}))
        self.initialize(valuesFromDb.get("wave", ""),
                        valuesFromDb.get("wave_commands", []), valuesFromDb.get("infos", {}))

    def initialize(self, wave="", wave_commands=None, infos=None):
        """Set values of scope
        Args:
            wave: the wave name, default is ""
            wave_commands: a list of command name that are to be launched in this wave. Defaut is None (empty list)
            infos: a dictionnary of additional info. Default is None (empty dict)
        Returns:
            this object
        """
        self.wave = wave
        self.wave_commands = wave_commands if wave_commands is not None else []
        self.infos = infos if infos is not None else {}
        return self


    def __str__(self):
        """
        Get a string representation of a wave.

        Returns:
            Returns the wave id (name).
        """
        return self.wave

    def getTools(self):
        """Return scope assigned tools as a list of mongo fetched tools dict
        Returns:
            list of defect raw mongo data dictionnaries
        """
        return Tool.fetchObjects({"wave": self.wave, "lvl": "wave"})

    def getAllTools(self):
        """Return all tools being part of this wave as a list of mongo fetched tools dict.
        Differs from getTools as it fetches all tools of the name and not only tools of level wave.
        Returns:
            list of defect raw mongo data dictionnaries
        """
        return Tool.fetchObjects({"wave": self.wave})



    def getDbKey(self):
        """Return a dict from model to use as unique composed key.
        Returns:
            A dict (1 key :"wave")
        """
        return {"wave": self.wave}

    def isLaunchableNow(self):
        """Returns True if the tool matches criteria to be launched 
        (current time matches one of interval object assigned to this wave)
        Returns:
            bool
        """
        intervals = Interval.fetchObjects({"wave": self.wave})
        for intervalModel in intervals:
            if Utils.fitNowTime(intervalModel.dated, intervalModel.datef):
                return True
        return False

    

