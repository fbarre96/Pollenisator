"""Controller for command object. Mostly handles conversion between mongo data and python objects"""
from pollenisator.core.controllers.controllerelement import ControllerElement
import bson

class CommandController(ControllerElement):
    """Inherits ControllerElement
    Controller for command object. Mostly handles conversion between mongo data and python objects"""


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