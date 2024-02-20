"""
This module contains the Tag class, which is used to represent a tag in the Pollenisator system.
"""

from typing import Dict, List, Optional, Tuple, Union, overload


class Tag:
    """
    Class to represent a tag in the Pollenisator system.
    
    Attributes:
        name (str): The name of the tag.
        color (str): The color of the tag.
        level (str): The level of the tag.
        notes (str): The notes of the tag.
    """
    @overload
    def __init__(self, name: str, color: str, level: str, notes: Optional[str]= None) -> None:
        ...
    @overload
    def __init__(self, tag: 'Tag') -> None:
        ...
    @overload
    def __init__(self, name: str, **kwargs: Dict[str, Optional[str]]) -> None:
        ...

    def __init__(self, *args, **kwargs) -> None:
        """
        Constructor for the Tag class.

        Args:
            args (Union[Tuple[str, str, str, Optional[str]], 'Tag', str, Dict[str, Optional[str]]]): 
                The arguments can be a tuple or list of name, color, level, and notes, or a Tag object, 
                or a string name, or a dictionary with keys "name", "color", "level", and "notes".
            kwargs (Dict[str, Optional[str]]): 
                The keyword arguments can be color, level, and notes.

        Raises:
            ValueError: If the first argument is not a tuple, list, Tag object, string, or dictionary.
        """

        if isinstance(args[0], tuple) or isinstance(args[0], list):
            name = args[0][0]
            color = args[0][1]
            level = args[0][2]
            try:
                notes = str(args[0][3])
            except IndexError:
                notes = ""
        elif isinstance(args[0], Tag):
            tag: Tag = args[0]
            name = str(tag.name)
            color = str(tag.color)
            level = str(tag.level)
            notes = str(tag.notes)
        elif isinstance(args[0], str):
            name = args[0]
            color = kwargs.get("color", None)
            level = kwargs.get("level", None)
            notes = kwargs.get("notes", None)
        elif isinstance(args[0], dict):
            name = args[0].get("name", "")
            color = args[0].get("color", None)
            level = args[0].get("level", None)
            notes = args[0].get("notes", None)
        else:
            raise ValueError("Tag constructor can't handle this type of argument: "+str(type(args[0]))+ ";"+str(args[0]))
        if kwargs.get("color", None) is not None:
            color = kwargs.get("color", None)
        if kwargs.get("level", None) is not None:
            level = kwargs.get("level", None)
        if kwargs.get("notes", None) is not None:
            notes = kwargs.get("notes", None)
        self.name: str = name
        self.color: str = color if color is not None else "transparent"
        self.level: str = level if level is not None else "info"
        self.notes: str = notes if notes is not None else ""

    def getData(self) -> Dict[str, Optional[str]]:
        """
        Get the data of the Tag object.

        Returns:
            Dict[str, Optional[str]]: A dictionary with keys "name", "color", "level", and "notes".
        """
        return {"name": self.name, "color": self.color, "level": self.level, "notes": self.notes}

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Get the attribute that can be used for searching.

        Returns:
            List[str]: A list containing the attribute "name".
        """
        return ["name"]
