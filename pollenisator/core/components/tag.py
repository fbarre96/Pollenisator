"""
This module contains the Tag class, which is used to represent a tag in the Pollenisator system.
TODO : Move to models ?
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
        self.name: str = ""
        self.do_init(args, kwargs)
        color = kwargs.get("color", None)
        level = kwargs.get("level", None)
        notes = kwargs.get("notes", None)
        self.color: str = color if color is not None else "transparent" # if no color is provided, set to transparent
        self.level: str = level if level is not None else "info" # if no level is provided, set to info
        self.notes: str = notes if notes is not None else "" # if no notes are provided, set to empty string

    def do_init(self, args, kwargs):
        """
        Helper method to initialize the Tag object based on the provided arguments.
        Args:
            args (Tuple): The positional arguments provided to the constructor.
                - Can be a tuple or list of (name, color, level, notes)
                - Can be a Tag object to copy from
                - Can be a string name, with optional kwargs for color, level, notes
                - Can be a dictionary with keys "name", "color", "level", and "notes"
            kwargs (Dict): The keyword arguments provided to the constructor:
                - Can include color, level, and notes
        Raises:
            ValueError: If the arguments are not in a recognized format.
        """
        if len(args) > 1:
            # init tag from basic arguments
            self._classical_init(*args, **kwargs)
        elif len(args) == 1:
            if isinstance(args[0], Tag):
                self.copy_tag(args[0])
            elif isinstance(args[0], (list, tuple)):
                self._init_from_list(args[0])
            elif isinstance(args[0], str):
                self.name = args[0]
                self.color = kwargs.get("color", None)
                self.level = kwargs.get("level", None)
                self.notes = kwargs.get("notes", None)
            elif isinstance(args[0], dict):
                self.name = args[0].get("name", "")
                self.color = args[0].get("color", None)
                self.level = args[0].get("level", None)
                self.notes = args[0].get("notes", None)
            else:
                raise ValueError("Tag constructor can't handle this type of argument: "+str(type(args[0]))+ ";"+str(args[0]))
        else:
            raise ValueError("Tag incorrectly constructed Got: "+str(args))

    def _init_from_list(self, list_or_tuple: Union[List, Tuple]) -> None:
        """
        Init method for the Tag class from a list or tuple.
        Args:
            list_or_tuple (Union[List, Tuple]): A tuple or list of name, color, level, and notes.
        Raises:
            IndexError: If the number of arguments is less than 2.
        """
        self.name = str(list_or_tuple[0])
        self.color = str(list_or_tuple[1])
        self.level = str(list_or_tuple[2])
        try:
            self.notes = str(list_or_tuple[3])
        except IndexError:
            self.notes = ""

    def copy_tag(self, tag: 'Tag') -> None:
        """
        Copy the values from another Tag object.
        Args:
            tag (Tag): The Tag object to copy from.
        """
        self.name = str(tag.name)
        self.color = str(tag.color)
        self.level = str(tag.level)
        self.notes = str(tag.notes)

    def _classical_init(self, *args, **kwargs) -> None:
        """
        Classical init method for the Tag class.
        Args:
            args (Tuple[str, str, str, Optional[str]]): A tuple or list of name, color, level, and notes.
            kwargs (Dict[str, Optional[str]]): The keyword arguments can be color, level, and notes.
        Raises:
            ValueError: If the number of arguments is less than 2.
        """
        self.name = args[0]
        self.color = args[1]
        try:
            self.level = args[2]
        except IndexError:
            self.level = kwargs.get("level", None)
        try:
            self.notes = str(args[3])
        except IndexError:
            self.notes = kwargs.get("notes", None)

    

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
