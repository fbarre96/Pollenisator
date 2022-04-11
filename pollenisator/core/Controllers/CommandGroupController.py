"""Controller for command group object. Mostly handles conversion between mongo data and python objects"""

from pollenisator.core.Controllers.ControllerElement import ControllerElement


class CommandGroupController(ControllerElement):
    """Inherits ControllerElement
    Controller for command group object. Mostly handles conversion between mongo data and python objects"""

    

    def getData(self):
        """Return command attributes as a dictionnary matching Mongo stored commands groups
        Returns:
            dict with keys name, commands,, sleep_between, max_thread, _id, tags and infos
        """
        return {"name": self.model.name, "indb":self.model.indb, "commands": self.model.commands, "sleep_between": self.model.sleep_between, "max_thread": self.model.max_thread,
                "_id": self.model.getId(), "tags": self.model.tags, "infos": self.model.infos}

    def getType(self):
        """Return a string describing the type of object
        Returns:
            "commandgroup" """
        return "commandgroup"