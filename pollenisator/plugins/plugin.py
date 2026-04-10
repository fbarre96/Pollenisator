"""A registry for all subclasses of Plugin
A plugin should:
1. return a PluginResult.empty() if not able to parse the file
2. parse the file to extract useful information
3. return a PluginResult containing objects to insert/upsert/update
   (the caller will persist them via apply_plugin_result)

"""
from typing import IO, Any, Dict, List, Optional, Tuple, Type
from abc import ABCMeta, abstractmethod
import shlex
import os
from pollenisator.core.components.logger_config import logger
from pollenisator.core.components.tag import Tag
from pollenisator.plugins.plugin_result import PluginResult

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
    default_plugin_flags = ["default"]

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

    def detect_cmdline(self, cmdline: str) -> bool|str:
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
        if os.path.basename(cmd_args[0]) == self.__class__.get_name():
            logger.info(f"Detected {self.__class__.__name__} plugin")
            return True
        elif os.path.basename(cmd_args[0].lower()) in self.__class__.default_bin_names \
            and all(flag in cmd_args for flag in self.default_plugin_flags):
            logger.info(f"Detected {self.__class__.__name__} plugin")
            return True
        elif os.path.basename(cmd_args[0].lower()) in self.__class__.default_bin_names \
            and "default" in self.default_plugin_flags:
            logger.info(f"Detected {self.__class__.__name__} default plugin")
            return "Default"
        return False

    @abstractmethod
    def Parse(self, pentest: str, file_opened: IO[bytes], **kwargs: Any) -> PluginResult:
        """
        Parse an opened file to extract information.

        Args:
            pentest (str): The name of the pentest.
            file_opened (BinaryIO): The opened file.
            **kwargs (Any): Additional parameters (not used).

        Returns:
            PluginResult: A result object containing:
                - notes: Notes to be inserted in tool giving direct info to pentester.
                - tags: A list of tags to be added to tool.
                - lvl: The level of the command executed to assign to given targets.
                - targets: A dict of composed keys allowing retrieve/insert from/into database targeted objects.
                - ips/ports/computers/users/shares: Objects to insert.
                - info_updates/tag_additions/...: Deferred DB operations.
                All fields are None when the plugin cannot parse the file.
        """
        notes = ""
        tags = [Tag("todo")]
        notes = file_opened.read().decode("utf-8", errors="ignore")
        return PluginResult(notes=notes, tags=tags, lvl="wave", targets={"wave": {"wave": "Imported"}})

    def getFilePath(self, commandExecuted: str) -> str:
        """Returns the output file path given in the executed command using getFileOutputArg

        Args:
            commandExecuted: the command that was executed with an output file inside.

        Returns:
            str: the path to file created
        """
        return self.getFileOutputPath(commandExecuted)
