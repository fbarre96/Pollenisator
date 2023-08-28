"""A registry for all subclasses of Plugin"""
REGISTRY = {}
import shlex
import os

def register_class(target_class):
    """Register the given class
    Args:
        target_class: type <class>
    """
    REGISTRY[target_class.__name__] = target_class()


class MetaPlugin(type):
    def __new__(meta, name, bases, class_dict):
        cls = type.__new__(meta, name, bases, class_dict)
        if name not in REGISTRY:
            register_class(cls)
        return cls


class Plugin(metaclass=MetaPlugin):
    """ Parent base plugin to be inherited
    Attributes:
        autoDetect: indicating to auto-detect that this plugin is able to auto detect.
    """
    autoDetect = True  # Authorize parsing function be used for autodetection
    default_bin_names = ["default"]

    def autoDetectEnabled(self):
        """Returns a boolean indicating if this plugin is able to recognize a file to be parsed by it.
        Returns: 
            bool
        """
        return self.__class__.autoDetect

    @classmethod
    def get_name(cls):
        return cls.__name__

    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " | tee "

    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".log.txt"

    def changeCommand(self, command, outputDir, toolname):
        """
        Summary: Complete the given command with the tool output file option and filename absolute path.
        Args:
            * command : the command line to complete
            * outputDir : the directory where the output file must be generated
            * toolname : the tool name (to be included in the output file name)
        Return:
            The command completed with the tool output file option and filename absolute path.
        """
        # default is append at the end
        if self.getFileOutputArg() not in command:
            return command + self.getFileOutputArg()+outputDir+toolname
        return command

    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        return commandExecuted.split(self.getFileOutputArg())[-1].strip()
    
    def detect_cmdline(self, cmdline):
        """Returns a boolean indicating if this plugin is able to recognize a command line as likely to output results for it.
        Args:
            cmdline: the command line to test
        Returns:
            bool
        """
        cmd_args = shlex.split(cmdline)
        if not cmd_args:
            return False
        if os.path.basename(cmd_args[0].lower()) in self.__class__.default_bin_names:
            return True
        return False

    def Parse(self, pentest, file_opened, **_kwargs):
        """
        Parse a opened file to extract information
        Args:
            file_opened: the open file
            _kwargs: not used
        Returns:
            a tuple with 4 values (All set to None if Parsing wrong file): 
                0. notes: notes to be inserted in tool giving direct info to pentester
                1. tags: a list of tags to be added to tool 
                2. lvl: the level of the command executed to assign to given targets
                3. targets: a list of composed keys allowing retrieve/insert from/into database targerted objects.
        """
        notes = ""
        tags = ["todo"]
        notes = file_opened.read().decode("utf-8")
        return notes, tags, "wave", {"wave": {"wave":"Imported"}}

    def getFilePath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        return self.getFileOutputPath(commandExecuted)
