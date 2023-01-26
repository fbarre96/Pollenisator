"""Controller for command object. Mostly handles conversion between mongo data and python objects"""
from pollenisator.core.controllers.controllerelement import ControllerElement
import bson

class CommandController(ControllerElement):
    """Inherits ControllerElement
    Controller for command object. Mostly handles conversion between mongo data and python objects"""

    def getData(self):
        """Return command attributes as a dictionnary matching Mongo stored commands
        Returns:
            dict with keys name,  text,  max_thread, types, _id, tags and infos
        """
        return {"name": self.model.name, "bin_path":self.model.bin_path, "plugin":self.model.plugin,  "text": self.model.text,
                "timeout": self.model.timeout,
                "indb":self.model.indb, "_id": self.model.getId(), "tags": self.model.tags, "infos": self.model.infos}

    def getType(self):
        """Return a string describing the type of object
        Returns:
            "command" """
        return "command"

    def actualize(self):
        """Ask the model to reload its data from database
        """
        if self.model is not None:
            self.model = self.model.__class__.fetchObject(
                {"_id": bson.ObjectId(self.model.getId())}, self.model.indb)