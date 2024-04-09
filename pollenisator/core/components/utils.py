"""Provide useful functions"""
import sys
import os
import subprocess
import time
from datetime import datetime
from threading import Timer
import json
import shutil
import re
from typing import Any, Dict, List, Optional, Union
from netaddr import IPNetwork
from netaddr.core import AddrFormatError
from bson import ObjectId
import dns.resolver
import werkzeug

from pollenisator.plugins.plugin import Plugin
from pollenisator.core.components.logger_config import logger
from pollenisator.core.components.tag import Tag

class JSONEncoder(json.JSONEncoder):
    """JSON encoder for custom types:
        - Converts bson.ObjectId to string ObjectId|<id>
        - Converts datetime to string using datatime.__str__
        - Converts bytes to string using utf-8
        - Converts Tag to string using Tag.getData()
    """

    def default(self, o):
        if isinstance(o, ObjectId):
            return "ObjectId|"+str(o)
        elif isinstance(o, datetime):
            return str(o)
        elif isinstance(o, Tag):
            return o.getData()
        elif isinstance(o, bytes):
            return str(o, 'utf-8')
        return json.JSONEncoder.default(self, o)

class JSONDecoder(json.JSONDecoder):
    """
    JSON decoder for custom types:
        - Converts string ObjectId|<id> to bson.ObjectId
        - Converts string datetime to datetime
        - Converts string Tag to Tag object
    """
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Constructor for the JSONDecoder class.

        Args:
            args (Any): Variable length argument list.
            kwargs (Any): Arbitrary keyword arguments.

        Inherits:
            json.JSONDecoder: The JSONDecoder class from the json module.
        """
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    # Override the object_hook function to convert custom types
    def object_hook(self, dct: Dict[Any, Any]) -> Dict[Any, Any]: # pylint: disable=method-hidden
        """
        Override the object_hook function to convert custom types.

        Args:
            dct (Dict[Any, Any]): The dictionary to process.

        Returns:
            Dict[Any, Any]: The processed dictionary with custom types converted.
        """
        for k,v in dct.items():
            if isinstance(v, list):
                for i, item in enumerate(v):
                    if str(item).startswith('ObjectId|'):
                        v[i] = ObjectId(str(item).split('ObjectId|')[1])
                dct[k] = v
            elif str(v).startswith('ObjectId|'):
                dct[k] = ObjectId(v.split('ObjectId|')[1])
        return dct



def loadPlugin(pluginName: str) -> Plugin:
    """
    Load a the plugin python corresponding to the given command name.
    The plugin must start with the command name and be located in plugins folder.

    Args:
        pluginName (str): The command name to load a plugin for.

    Returns:
        Any: The module plugin loaded or default plugin if not found.
    """
    from pollenisator.plugins.plugin import REGISTRY
    # Load plugins
    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(dir_path, "../../plugins/")
    # Load plugins
    sys.path.insert(0, path)
    try:
        # Dynamic import, raises ValueError if not found
        if not pluginName.endswith(".py"):
            pluginName += ".py"
        # trigger exception if plugin does not exist
        __import__(pluginName[:-3])
        return REGISTRY[pluginName[:-3]]  # removes the .py
    except ValueError:
        __import__("Default")
        return REGISTRY["Default"]
    except FileNotFoundError:
        __import__("Default")
        return REGISTRY["Default"]
    except ModuleNotFoundError:
        __import__("Default")
        return REGISTRY["Default"]
    

def listPlugin() -> List[str]:
    """
    List the plugins.

    Returns:
        List[str]: The list of plugin file names.
    """
    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(dir_path, "../../plugins/")
    # Load plugins
    sys.path.insert(0, path)
    plugin_list = os.listdir(path)
    plugin_list = [x for x in plugin_list if x.endswith(
        ".py") and x != "__pycache__" and x != "__init__.py" and x != "plugin.py"]
    return plugin_list

def detectPlugins(pentest: str, upfile: werkzeug.datastructures.FileStorage, cmdline: str, ext: str) -> List[Dict[str, Any]]:
    """
    Detect which plugins to use on the uploaded file, and get their results.

    Args:
        pentest (str): The pentest object.
        upfile (werkzeug.FileStorag): The uploaded file object.
        cmdline (str): The command line string.
        ext (str): The file extension.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing the results of each plugin.
    """
    results = []
    for pluginName in listPlugin():
        result: Dict[str, Any] = {"tags":[]}
        mod = loadPlugin(pluginName)
        if mod.autoDetectEnabled():
            try:
                notes, tags, lvl, targets = mod.Parse(pentest, upfile.stream, cmdline=cmdline, ext=ext, filename=upfile.filename)
            except Exception as e:
                logger.error("Error in plugin %s: %s", pluginName, e)
                notes, tags, lvl, targets  = None, None, None, None
            upfile.stream.seek(0)
            if notes is not None and tags is not None:
                result["tags"] = tags
                result["notes"] = notes
                result["lvl"] = lvl
                result["targets"] = targets
                result["plugin"] = pluginName
                results.append(result)
    return results

def detectPluginsWithCmd(cmdline: str) -> List[str]:
    """
    Detect plugins with a given command line.

    Args:
        cmdline (str): The command line string.

    Returns:
        List[str]: A list of detected plugin names. If no plugins are detected, returns ["Default"].
    """
    find_non_default_plugin = False
    foundPlugins = []
    for pluginName in listPlugin():
        mod = loadPlugin(pluginName)
        if mod.autoDetectEnabled():
            print("Valeur de find_non_default_plugin 1 : ", find_non_default_plugin)
            if mod.detect_cmdline(cmdline) is True:
                print("### DETECTED PLUGIN : ", pluginName)
                find_non_default_plugin = True
                foundPlugins.append(pluginName)
            print("Valeur de find_non_default_plugin 2: ", find_non_default_plugin)
            if mod.detect_cmdline(cmdline) == "Default" and not find_non_default_plugin:
                print("### DETECTED DEFAULT PLUGIN : ", pluginName)
                foundPlugins = [pluginName]
    if not foundPlugins:
        return ["Default"]
    print("### FOUND PLUGINGS : ", foundPlugins)
    return foundPlugins

def isIp(domain_or_networks: str) -> bool:
    """
    Check if the given scope string is a network IP or a domain.

    Args:
        domain_or_networks (str): The domain string or the network IPv4 range string.

    Returns:
        bool: Returns True if it is a network IPv4 range, False if it is a domain (any other possible case).
    """
    regex_network_ip = r"((?:[0-9]{1,3}\.){3}[0-9]{1,3})$"
    ipSearch = re.match(regex_network_ip, domain_or_networks)
    return ipSearch is not None

def isNetworkIp(domain_or_networks: str) -> bool:
    """
    Check if the given scope string is a network IP or a domain.

    Args:
        domain_or_networks (str): The domain string or the network IPv4 range string.

    Returns:
        bool: Returns True if it is a network IPv4 range, False if it is a domain (any other possible case).
    """
    try:
        IPNetwork(domain_or_networks)
    except AddrFormatError:
        return False
    return True


def splitRange(rangeIp: str) -> List[IPNetwork]:
    """
    Check if the given range string is bigger than a /24, if it is, splits it in many /24.

    Args:
        rangeIp (str): Network IPv4 range string.

    Returns:
        List[IPNetwork]: A list of IPNetwork objects corresponding to the range given as /24s.
        If the entry range is smaller than a /24 (like /25 ... /32) the list will be empty.
    """
    ip = IPNetwork(rangeIp)
    subnets = list(ip.subnet(24))
    return subnets


def getDefaultWorkerCommandsFile() -> str:
    """
    Get the default worker commands file path.

    Returns:
        str: The path to the default worker commands file.
    """
    return os.path.join(getMainDir(), "config", "worker_commands.json")

def getDefaultCommandsFile() -> str:
    """
    Get the default commands file path.

    Returns:
        str: The path to the default commands file.
    """
    return os.path.join(getMainDir(), "config", "default_commands.json")

def getDefaultCheatsheetFile() -> str:
    """
    Get the default cheatsheet commands file path.

    Returns:
        str: The path to the default cheatsheet commands file.
    """
    return os.path.join(getMainDir(), "config", "default_cheatsheet.json")

# def resetUnfinishedTools() -> None:
#     """
#     Reset all tools running to a ready state. This is useful if a command was running on a worker and the auto scanning was interrupted.
#     """
#     # test all the cases if datef is defined or not.
#     # Normally, only the first one is necessary
#     from pollenisator.core.models.tool import Tool
#     tools = Tool.fetchObjects({"datef": "None", "scanner_ip": {"$ne": "None"}})
#     for tool in tools:
#         tool.markAsNotDone()
#     tools = Tool.fetchObjects({"datef": "None", "dated": {"$ne": "None"}})
#     for tool in tools:
#         tool.markAsNotDone()
#     tools = Tool.fetchObjects(
#         {"datef": {"$exists": False}, "dated": {"$ne": "None"}})
#     for tool in tools:
#         tool.markAsNotDone()
#     tools = Tool.fetchObjects(
#         {"datef": {"$exists": False}, "scanner_ip": {"$ne": "None"}})
#     for tool in tools:
#         tool.markAsNotDone()


def stringToDate(datestring: str) -> Optional[datetime]:
    """
    Converts a string with format '%d/%m/%Y %H:%M:%S' to a python date object.

    Args:
        datestring (str): The date string to convert.
    Raises:
        ValueError: If the given string is not in the correct format.
    Returns:
        Optional[datetime]: The date python object if the given string is successfully converted, None otherwise.
    """
    ret = None
    if isinstance(datestring, str):
        if datestring != "None":
            try:
                ret = datetime.strptime(
                    datestring, '%d/%m/%Y %H:%M:%S')
            except ValueError as e:
                raise e
    return ret


def fitNowTime(dated: Optional[str], datef: Optional[str]) -> bool:
    """
    Check the current time on the machine is between the given start and end date.

    Args:
        dated (Optional[str]): The starting date for the interval.
        datef (Optional[str]): The ending date for the interval.

    Returns:
        bool: True if the current time is between the given interval. False otherwise.
        If one of the args is None, returns False.
    """
    today = datetime.now()
    if dated is None or datef is None:
        return False
    try:
        date_start = stringToDate(dated)
        date_end = stringToDate(datef)
    except ValueError:
        return False
    if date_start is None or date_end is None:
        return False
    return today > date_start and date_end > today


def execute(command: str, timeout: Optional[Union[float, datetime]] = None, printStdout: bool = True) -> int:
    """
    Execute a bash command and print output.

    Args:
        command (str): A bash command.
        timeout (Optional[Union[float, datetime]]): A date in the future when the command will be stopped if still running or None to not use this option. Default is None.
        printStdout (bool): A boolean indicating if the stdout should be printed. Default is True.

    Returns:
        int: The return code of this command.

    Raises:
        KeyboardInterrupt: If the command was interrupted by a KeyboardInterrupt (Ctrl+c).
    """
    try:
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        time.sleep(1) #HACK Break if not there when launching fast custom tools on local host
        float_timeout = None
        timer = None
        try:
            if timeout is not None:
                if isinstance(timeout, float):
                    timer = Timer(timeout, proc.kill)
                    timer.start()
                    float_timeout = timeout
                elif isinstance(timeout, datetime):
                    if timeout.year < datetime.now().year+1:
                        float_timeout = (timeout-datetime.now()).total_seconds()
                        timer = Timer(float_timeout, proc.kill)
                        timer.start()
                else:
                    logger.error(
                        "ERROR in command execution: timeout must be a float or a datetime object")
                    return -1
            raw_stdout, raw_stderr = proc.communicate(None, float_timeout)
            if printStdout:
                stdout = raw_stdout.decode('utf-8')
                stderr = raw_stderr.decode('utf-8')
                if str(stdout) != "":
                    print(str(stdout))
                if str(stderr) != "":
                    print(str(stderr))
        except Exception as e:
            logger.error("ERROR in command execution of command %s: %s", command, e)
            proc.kill()
            return -1
        finally:
            if timer is not None:
                timer.cancel()
        return proc.returncode
    except KeyboardInterrupt as e:
        raise e


def performLookUp(domain: str, nameservers: Optional[List[str]] = None) -> Optional[str]:
    """
    Uses the dns.resolver module to get an IP from a domain.

    Args:
        domain (str): The domain to look for in DNS.
        nameservers (Optional[List[str]]): A list of nameservers to use for the DNS lookup. If not provided, uses ['8.8.8.8', '1.1.1.1'].

    Returns:
        Optional[str]: The IP found from DNS records, None if failed.
    """
    my_resolver = dns.resolver.Resolver()
    my_resolver.timeout = 1
    my_resolver.lifetime = 1
    my_resolver.nameservers = nameservers if nameservers is not None else ['8.8.8.8', '1.1.1.1']
    try:
        answer = my_resolver.query(domain, 'A')
        if answer:
            res = str(answer[0].to_text())
            if res != "0.0.0.0":
                return res
    except KeyError:
        return None
    except Exception:
        return None
    return None

    


def loadCfg(cfgfile: str) -> Dict[str, Any]:
    """
    Load a json config file.

    Args:
        cfgfile (str): The path to a json config file.

    Raises:
        FileNotFoundError: If the given file does not exist.

    Returns:
        Dict[str, Any]: The json converted values of the config file.
    """
    default_tools_infos = dict()
    try:
        with open(cfgfile, "r", encoding="utf-8") as f:
            default_tools_infos = json.loads(f.read())
    except FileNotFoundError as e:
        raise e

    return default_tools_infos


def getServerConfigFolder() -> str:
    """
    Get the server configuration folder path. If the folder does not exist, it is created.

    Returns:
        str: The path to the server configuration folder.
    """
    c = os.path.join(os.path.expanduser("~"), ".config/pollenisator/")
    os.makedirs(c, exist_ok=True)
    return c

def loadServerConfig() -> Dict[str, Any]:
    """
    Load the server configuration from the config/server.cfg file. If the file does not exist, it tries to create it from a sample config file.

    Returns:
        Dict[str, Any]: The json converted values of the server config file.

    Raises:
        SystemExit: If the config file or the sample config file does not exist, or if there is a permission error when trying to create the config file.
    """
    config_file = os.path.join(getServerConfigFolder(), "server.cfg")
    sample_config_file = os.path.join(getMainDir(),"config/", "serverSample.cfg")
    if not os.path.isfile(config_file):
        if os.path.isfile(sample_config_file):
            try:
                shutil.copyfile(sample_config_file, config_file)
            except PermissionError:
                logger.error("Permission denied when trying to create a config file\n Please create the file %s (you can use the serverSample.cfg as a base)", os.path.normpath(config_file))
                sys.exit(0)
        else:
            logger.warning("Config file not found inside %s, please create one based on the provided serverSample.cfg inside the same directory.", os.path.normpath(config_file))
            sys.exit(0)
    return loadCfg(config_file)


def saveServerConfig(configDict: Dict[str, Any]) -> None:
    """
    Saves data in configDict to config/server.cfg as json.

    Args:
        configDict (Dict[str, Any]): Data to be stored in config/server.cfg.
    """
    configFile = os.path.join(getServerConfigFolder(),"server.cfg")
    with open(configFile, "w", encoding="utf8") as f:
        f.write(json.dumps(configDict))


def getMainDir() -> str:
    """
    Get the main directory of the Pollenisator application.

    Returns:
        str: The path to the main directory of the Pollenisator application.
    """
    p = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), "../../")
    return p

def checkCommandService(allowed_ports_services: List[str], port: str, proto: str, service: str) -> bool:
    """
    Check if a given port and protocol combination is allowed by a list of allowed ports and services.

    Args:
        allowed_ports_services (List[str]): A list of allowed ports and services in the format "proto/port-service".
        port (str): The port to check.
        proto (str): The protocol to check.
        service (str): The service to check.

    Returns:
        bool: True if the port and protocol combination is allowed, False otherwise.
    """
    for i, elem in enumerate(allowed_ports_services):
        elem_stripped = elem.strip()
        if not elem_stripped.startswith(("tcp/", "udp/")):
            allowed_ports_services[i] = "tcp/"+elem_stripped.strip()
    for allowed in allowed_ports_services:
        proto_range = "udp" if allowed.startswith("udp/") else "tcp"
        maybeRange = str(allowed)[4:].split("-")
        startAllowedRange = endAllowedRange = -1
        if len(maybeRange) == 2:
            try:
                startAllowedRange = int(maybeRange[0])
                endAllowedRange = int(maybeRange[1])
            except ValueError:
                startAllowedRange = endAllowedRange = -1
        if proto + "/" + port == allowed or proto + "/" + service == allowed \
            or (
                proto == proto_range \
                and startAllowedRange <= int(port) <= endAllowedRange
            ):
            return True
    return False
