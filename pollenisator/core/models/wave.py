"""Wave Model. Stores which command should be launched and associates Interval and Scope"""

from bson.objectid import ObjectId
from pollenisator.core.models.tool import Tool
from pollenisator.core.models.element import Element
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.interval import Interval
import pollenisator.core.components.utils as utils
from pollenisator.core.models.scope import Scope


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
                        possible keys with default values are : _id(None), parent(None), infos({}),
                        wave(""), wave_commands([])
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(valuesFromDb.get("_id", None), valuesFromDb.get("parent", None), valuesFromDb.get("infos", {}))
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

    def getData(self):
        """Return wave attributes as a dictionnary matching Mongo stored waves
        Returns:
            dict with keys wave, wave_commands, infos
        """
        return {"wave": self.wave, "wave_commands": self.wave_commands, "_id": self.getId(), "infos": self.infos}


    def __str__(self):
        """
        Get a string representation of a wave.

        Returns:
            Returns the wave id (name).
        """
        return self.wave
    
    @classmethod
    def getSearchableTextAttribute(cls):
        return ["wave"]

    

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
            if utils.fitNowTime(intervalModel.dated, intervalModel.datef):
                return True
        return False

    

