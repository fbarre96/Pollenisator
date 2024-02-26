"""A registry for all subclasses of Plugin"""
from typing import IO, Any, Dict, List, Optional, Tuple, Type
from abc import ABCMeta, abstractmethod
import shlex
import os
from pollenisator.core.components.tag import Tag

REGISTRY: Dict[str, 'Plugin'] = {}

def register_class(target_class: Type) -> None:
    """Register the given class
    Args:
        target_class (Type): type <class>
    """
    REGISTRY[target_class.__name__] = target_class()


class MetaPlugin(type):
    def __new__(meta, name, bases, class_dict):
        cls = type.__new__(meta, name, bases, class_dict)
        if name not in REGISTRY:
            register_class(cls)
        return cls
# Create a new metaclass that inherits from both ABCMeta and the custom MetaPlugin
class AbstractMetaPlugin(ABCMeta, MetaPlugin):
    pass


class Plugin(metaclass=AbstractMetaPlugin):
    """
    Parent base plugin to be inherited
    Attributes:
        autoDetect: indicating to auto-detect that this plugin is able to auto detect.
        default_bin_names: list of default binary names (ex: "nmap" for "nmap", ["dirsearch", "dirsearch.py"] for dirsearch, etc.)
    """
    autoDetect = True  # Authorize parsing function be used for autodetection
    default_bin_names = ["default"]

    def autoDetectEnabled(self) -> bool:
        """
        Returns a boolean indicating if this plugin is able to recognize a file to be parsed by it.

        Returns: 
            bool
        """
        return self.__class__.autoDetect

    @classmethod
    def get_name(cls) -> str:
        """
        Returns the name of the plugin

        Returns:
            str
        """
        return cls.__name__

    @abstractmethod
    def getFileOutputArg(self) -> str:
        """
        Returns the command line parameter giving the output file

        Returns:
            str: for example " -o " or by default " | tee "
        """
        return " | tee "

    @abstractmethod
    def getFileOutputExt(self) -> str:
        """
        Returns the expected file extension for this command result file

        Returns:
            str: default to .log.txt
        """
        return ".log.txt"

    def changeCommand(self, command: str, outputDir: str, toolname: str) -> str:
        """
        Complete the given command with the tool output file option and filename absolute path.

        Args:
            command (str): The command line to complete.
            outputDir (str): The directory where the output file must be generated.
            toolname (str): The tool name (to be included in the output file name).

        Returns:
            str: The command completed with the tool output file option and filename absolute path.
        """
        # default is append at the end
        if self.getFileOutputArg() not in command:
            return command + self.getFileOutputArg()+outputDir+toolname
        return command

    @abstractmethod
    def getFileOutputPath(self, commandExecuted: str) -> str:
        """
        Returns the output file path given in the executed command using getFileOutputArg

        Args:
            commandExecuted: the command that was executed with an output file inside.

        Returns:
            str: the path to file created
        """
        return commandExecuted.split(self.getFileOutputArg())[-1].strip()

    @abstractmethod
    def getTags(self) -> Dict[str, Tag]:
        """
        Returns a dictionnary of tags that can be added by this plugin. Useful to be able to list all tags that can be added by all plugins.

        Returns:
            Dict[str, Tag]: a dictionnary of tags that can be added by this plugin
        """
        return {"todo": Tag("todo", "transparent", "todo", None)}

    def detect_cmdline(self, cmdline: str) -> bool:
        """
        Returns a boolean indicating if this plugin is able to recognize a command line as likely to output results for it.

        Args:
            cmdline (str): The command line to test.

        Returns:
            bool: True if the command line is recognized by the plugin, False otherwise.
        """
        cmd_args = shlex.split(cmdline)
        if not cmd_args:
            return False
        if os.path.basename(cmd_args[0].lower()) in self.__class__.default_bin_names:
            return True
        return False

    @abstractmethod
    def Parse(self, pentest: str, file_opened: IO[bytes], **kwargs: Any) -> Tuple[Optional[str], Optional[List[Tag]], Optional[str], Optional[Dict[str, Optional[Dict[str, Optional[str]]]]]]:
        """
        Parse an opened file to extract information.

        Args:
            pentest (str): The name of the pentest.
            file_opened (BinaryIO): The opened file.
            **kwargs (Any): Additional parameters (not used).

        Returns:
            Tuple[Optional[str], Optional[List[Tag]], Optional[str], Optional[Dict[str, Dict[str, str]]]]: A tuple with 4 values (All set to None if Parsing wrong file): 
                0. notes (str): Notes to be inserted in tool giving direct info to pentester.
                1. tags (List[Tag]): A list of tags to be added to tool.
                2. lvl (str): The level of the command executed to assign to given targets.
                3. targets (Tuple[Optional[str], Optional[List[Tag]], Optional[str], Optional[Dict[str, Optional[Dict[str, Optional[str]]]]]]): A list of composed keys allowing retrieve/insert from/into database targeted objects.
        """
        notes = ""
        tags = [Tag("todo")]
        notes = file_opened.read().decode("utf-8", errors="ignore")
        return notes, tags, "wave", {"wave": {"wave":"Imported"}}

    def getFilePath(self, commandExecuted: str) -> str:
        """Returns the output file path given in the executed command using getFileOutputArg

        Args:
            commandExecuted: the command that was executed with an output file inside.

        Returns:
            str: the path to file created
        """
        return self.getFileOutputPath(commandExecuted)
