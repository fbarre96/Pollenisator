"""Controller for command object. 
Mostly handles conversion between mongo data and python objects"""

from pollenisator.core.controllers.controllerelement import ControllerElement

class CommandController(ControllerElement):
    """Inherits ControllerElement
    Controller for command object. Mostly handles conversion between mongo data and python objects"""


    def getType(self) -> str:
        """
        Return a string describing the type of object.

        Returns:
            str: A string "command" indicating the type of object.
        """
        return "command"
