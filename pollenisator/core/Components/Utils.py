"""Provide useful functions"""
import sys
import os
import socket
import subprocess
import time
from datetime import datetime
from threading import Timer
import json
import shutil
from netaddr import IPNetwork
from netaddr.core import AddrFormatError
from bson import ObjectId
import logging
import dns.resolver

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return "ObjectId|"+str(o)
        elif isinstance(o, datetime):
            return str(o)
        return json.JSONEncoder.default(self, o)

class JSONDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)
        
    def object_hook(self, dct):
        for k,v in dct.items():
            if 'ObjectId|' in str(v):
                dct[k] = ObjectId(v.split('ObjectId|')[1])
        return dct



def loadPlugin(pluginName):
    """
    Load a the plugin python corresponding to the given command name.
    The plugin must start with the command name and be located in plugins folder.
    Args:
        pluginName: the command name to load a plugin for

    Returns:
        return the module plugin loaded or default plugin if not found.
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

def listPlugin():
    """
    List the plugins.
    Returns:
        return the list of plugins file names.
    """
    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(dir_path, "../../plugins/")
    # Load plugins
    sys.path.insert(0, path)
    plugin_list = os.listdir(path)
    plugin_list = [x for x in plugin_list if x.endswith(
        ".py") and x != "__pycache__" and x != "__init__.py" and x != "plugin.py"]
    return plugin_list


def isIp(domain_or_networks):
    """
    Check if the given scope string is a network ip or a domain.
    Args:
        domain_or_networks: the domain string or the network ipv4 range string
    Returns:
        Returns True if it is a network ipv4 range, False if it is a domain (any other possible case).
    """
    import re
    regex_network_ip = r"((?:[0-9]{1,3}\.){3}[0-9]{1,3})$"
    ipSearch = re.match(regex_network_ip, domain_or_networks)
    return ipSearch is not None


def isNetworkIp(domain_or_networks):
    """
    Check if the given scope string is a network ip or a domain.
    Args:
        domain_or_networks: the domain string or the network ipv4 range string
    Returns:
        Returns True if it is a network ipv4 range, False if it is a domain (any other possible case).
    """
    try:
        IPNetwork(domain_or_networks)
    except AddrFormatError:
        return False
    return True


def splitRange(rangeIp):
    """
    Check if the given range string is bigger than a /24, if it is, splits it in many /24.
    Args:
        rangeIp: network ipv4 range string
    Returns:
        Returns a list of IpNetwork objects corresponding to the range given as /24s.
        If the entry range is smaller than a /24 (like /25 ... /32) the list will be empty.
    """
    ip = IPNetwork(rangeIp)
    subnets = list(ip.subnet(24))
    return subnets


def resetUnfinishedTools():
    """
    Reset all tools running to a ready state. This is useful if a command was running on a worker and the auto scanning was interrupted.
    """
    # test all the cases if datef is defined or not.
    # Normally, only the first one is necessary
    from pollenisator.core.Models.Tool import Tool
    tools = Tool.fetchObjects({"datef": "None", "scanner_ip": {"$ne": "None"}})
    for tool in tools:
        tool.markAsNotDone()
    tools = Tool.fetchObjects({"datef": "None", "dated": {"$ne": "None"}})
    for tool in tools:
        tool.markAsNotDone()
    tools = Tool.fetchObjects(
        {"datef": {"$exists": False}, "dated": {"$ne": "None"}})
    for tool in tools:
        tool.markAsNotDone()
    tools = Tool.fetchObjects(
        {"datef": {"$exists": False}, "scanner_ip": {"$ne": "None"}})
    for tool in tools:
        tool.markAsNotDone()


def stringToDate(datestring):
    """Converts a string with format '%d/%m/%Y %H:%M:%S' to a python date object.
    Args:
        datestring: Returns the date python object if the given string is successfully converted, None otherwise"""
    ret = None
    if isinstance(datestring, str):
        if datestring != "None":
            ret = datetime.strptime(
                datestring, '%d/%m/%Y %H:%M:%S')
    return ret


def fitNowTime(dated, datef):
    """Check the current time on the machine is between the given start and end date.
    Args:
        dated: the starting date for the interval
        datef: the ending date for the interval
    Returns:
        True if the current time is between the given interval. False otherwise.
        If one of the args is None, returns False."""
    today = datetime.now()
    date_start = stringToDate(dated)
    date_end = stringToDate(datef)
    if date_start is None or date_end is None:
        return False
    return today > date_start and date_end > today


def execute(command, timeout=None, printStdout=True):
    """
    Execute a bash command and print output

    Args:
        command: A bash command
        timeout: a date in the futur when the command will be stopped if still running or None to not use this option, default as None.
        printStdout: A boolean indicating if the stdout should be printed. Default to True.

    Returns:
        Return the return code of this command

    Raises:
        Raise a KeyboardInterrupt if the command was interrupted by a KeyboardInterrupt (Ctrl+c)
    """

    try:
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        time.sleep(1) #HACK Break if not there when launching fast custom tools on local host
        try:
            if timeout is not None:
                if isinstance(timeout, float):
                    timeout = (timeout-datetime.now()).total_seconds()
                    timer = Timer(timeout, proc.kill)
                    timer.start()
                else:
                    if timeout.year < datetime.now().year+1:
                        timeout = (timeout-datetime.now()).total_seconds()
                        timer = Timer(timeout, proc.kill)
                        timer.start()
            stdout, stderr = proc.communicate(None, timeout)
            if printStdout:
                stdout = stdout.decode('utf-8')
                stderr = stderr.decode('utf-8')
                if str(stdout) != "":
                    print(str(stdout))
                if str(stderr) != "":
                    print(str(stderr))
        except Exception as e:
            logging.error(f"ERROR in command execution of command {command}: {e}")
            proc.kill()
            return -1
        finally:
            if timeout is not None:
                if isinstance(timeout, float):
                    timer.cancel()
                else:
                    if timeout.year < datetime.now().year+1:
                        timer.cancel()
        return proc.returncode
    except KeyboardInterrupt as e:
        raise e


def performLookUp(domain, nameservers=['8.8.8.8', '1.1.1.1']):
    """
    Uses the socket module to get an ip from a domain.

    Args:
        domain: the domain to look for in dns

    Returns:
        Return the ip found from dns records, None if failed.
    """
    my_resolver = dns.resolver.Resolver()
    my_resolver.timeout = 1
    my_resolver.lifetime = 1
    my_resolver.nameservers = nameservers
    try: 
        answer = my_resolver.query(domain, 'A')
        if answer:
            res = answer[0].to_text()
            if res != "0.0.0.0":
                return res
    except dns.resolver.LifetimeTimeout:
        return None
    return None

    


def loadCfg(cfgfile):
    """
    Load a json config file.
    Args:
        cfgfile: the path to a json config file
    Raises:
        FileNotFoundError if the given file does not exist
    Returns:
        Return the json converted values of the config file.
    """
    default_tools_infos = dict()
    try:
        with open(cfgfile, "r") as f:
            default_tools_infos = json.loads(f.read())
    except FileNotFoundError as e:
        raise e

    return default_tools_infos


def getServerConfigFolder():
    c = os.path.join(os.path.expanduser("~"), ".config/pollenisator/")
    try:
        os.makedirs(c)
    except:
        pass
    return c

def getDefaultWorkerCommandsFile():
    return os.path.join(getMainDir(), "config", "worker_commands.json")

def getDefaultCommandsFile():
    return os.path.join(getMainDir(), "config", "default_commands.json")

def loadServerConfig():
    """Return data converted from json inside config/server.cfg
    Returns:
        Json converted data inside config/server.cfg
    """
    config_file = os.path.join(getServerConfigFolder(), "server.cfg")
    sample_config_file = os.path.join(getMainDir(),"config/", "serverSample.cfg")
    if not os.path.isfile(config_file):
        if os.path.isfile(sample_config_file):
            try:
                shutil.copyfile(sample_config_file, config_file)
            except PermissionError:
                (f"Permission denied when trying to create a config file\n Please create the file {os.path.normpath(config_file)} (you can use the serverSample.cfg as a base)")
                sys.exit(0)
        else:
            logging.waring(f"Config file not found inside {os.path.normpath(config_file)}, please create one based on the provided serverSample.cfg inside the same directory.")
            sys.exit(0)
    return loadCfg(config_file)


def saveServerConfig(configDict):
    """Saves data in configDict to config/server.cfg as json
    Args:
        configDict: data to be stored in config/server.cfg
    """
    configFile = os.path.join(getServerConfigFolder(),"server.cfg")
    with open(configFile, "w") as f:
        f.write(json.dumps(configDict))


def getValidMarkIconPath():
    """Returns:
         a validation mark icon path
    """
    p = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), "../../icon/done_tool.png")
    return p


def getBadMarkIconPath():
    """Returns:
         a bad mark icon path
    """
    p = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), "../../icon/cross.png")
    return p


def getWaitingMarkIconPath():
    """Returns:
         a waiting icon path
    """
    p = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), "../../icon/waiting.png")
    return p


def getHelpIconPath():
    """Returns:
         a help icon path
    """
    p = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), "../../icon/help.png")
    return p


def getIconDir():
    """Returns:
        the icon directory path
    """
    p = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), "../../icon/")
    return p


def getMainDir():
    """Returns:
        the pollenisator main folder
    """
    p = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), "../../")
    return p

def checkCommandService(allowed_ports_services, port, proto, service):
    for i, elem in enumerate(allowed_ports_services):
        if not(elem.strip().startswith("tcp/") or elem.strip().startswith("udp/")):
            allowed_ports_services[i] = "tcp/"+str(elem.strip())
    for allowed in allowed_ports_services:
        protoRange = "udp" if allowed.startswith("udp/") else "tcp"
        maybeRange = str(allowed)[4:].split("-")
        startAllowedRange = -1
        endAllowedRange = -1
        if len(maybeRange) == 2:
            try:
                startAllowedRange = int(maybeRange[0])
                endAllowedRange = int(maybeRange[1])
            except ValueError:
                pass
        if (proto+"/"+port == allowed) or \
            (proto+"/"+service == allowed) or \
            (proto == protoRange and
                int(port) >= int(startAllowedRange) and
                int(port) <= int(endAllowedRange)):
            return True
    return False


