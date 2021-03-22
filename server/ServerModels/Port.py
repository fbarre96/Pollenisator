from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Models.Port import Port
from core.Controllers.PortController import PortController
from server.ServerModels.Tool import ServerTool, delete as tool_delete
from server.ServerModels.Defect import delete as defect_delete
from server.ServerModels.Element import ServerElement
from core.Components.Utils import JSONEncoder
import json
from server.permission import permission
mongoInstance = MongoCalendar.getInstance()

class ServerPort(Port, ServerElement):
    
    def __init__(self, pentest="", *args, **kwargs):
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        mongoInstance.connectToDb(self.pentest)
        super().__init__(*args, **kwargs)


    def getParentId(self):
        mongoInstance.connectToDb(self.pentest)
        return mongoInstance.find("ips", {"ip": self.ip}, False)["_id"]

    def addAllTool(self, command_name, wave_name, scope, check=True):
        """
        Add the appropriate tools (level check and wave's commands check) for this port.

        Args:
            command_name: The command that we want to create all the tools for.
            wave_name: name of the was to fetch allowed commands from
            scope: a scope matching this tool (should only be used by network level tools)
            check: A boolean to bypass checks. Force adding this command tool to this port if False. Default is True
        """
        mongoInstance.connectToDb(self.pentest)
        if not check:
            newTool = ServerTool(self.pentest)
            newTool.initialize(command_name, wave_name, scope,
                               self.ip, self.port, self.proto, "port")
            newTool.addInDb()
            return
        # retrieve wave's command
        wave = mongoInstance.find(
            "waves", {"wave": wave_name}, False)
        commands = wave["wave_commands"]
        try:
            index = commands.index(command_name)
            # retrieve the command level
            command = mongoInstance.findInDb(self.pentest,
                                             "commands", {"name": commands[index]}, False)
            if command["lvl"] == "port":
                # 3. checking if the added port fit into the command's allowed service
                # 3.1 first, default the selected port as tcp if no protocole is defined.
                allowed_ports_services = command["ports"].split(",")
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
                    if (self.proto+"/"+self.port == allowed) or \
                       (self.proto+"/"+self.service == allowed) or \
                       (self.proto == protoRange and
                           int(self.port) >= int(startAllowedRange) and
                            int(self.port) <= int(endAllowedRange)):
                        # finally add tool
                        newTool = ServerTool(self.pentest)
                        newTool.initialize(
                            command_name, wave_name, scope, self.ip, self.port, self.proto, "port")
                        newTool.addInDb()
        except ValueError:
            pass
    
    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        mongoInstance.connectToDb(pentest)
        ds = mongoInstance.find(cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            # disabling this error as it is an abstract function
            yield cls(pentest, d)  #  pylint: disable=no-value-for-parameter
    
    @classmethod
    def fetchObject(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        mongoInstance.connectToDb(pentest)
        d = mongoInstance.find(cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls(pentest, d) 

    def addInDb(self):
        return insert(self.pentest, PortController(self).getData())

    def update(self):
        return update("ports", ObjectId(self._id), PortController(self).getData())

@permission("pentester")
def delete(pentest, port_iid):
    mongoInstance.connectToDb(pentest)

    port_o = ServerPort(pentest, mongoInstance.find("ports", {"_id":ObjectId(port_iid)}, False))
    tools = mongoInstance.find("tools", {"port": port_o.port, "proto": port_o.proto,
                                             "ip": port_o.ip}, True)
    for tool in tools:
        tool_delete(pentest, tool["_id"])
    defects = mongoInstance.find("defects", {"port": port_o.port, "proto": port_o.proto,
                                                "ip": port_o.ip}, True)
    for defect in defects:
        defect_delete(pentest, defect["_id"])
    res = mongoInstance.delete("ports", {"_id": ObjectId(port_iid)}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count
@permission("pentester")
def insert(pentest, body):
    mongoInstance.connectToDb(pentest)
    port_o = ServerPort(pentest, body)
    base = port_o.getDbKey()
    existing = mongoInstance.find(
            "ports", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    parent = port_o.getParentId()
    ins_result = mongoInstance.insert("ports", body, parent)
    iid = ins_result.inserted_id
    # adding the appropriate tools for this port.
    # 1. fetching the wave's commands
    waves = mongoInstance.find("waves", {})
    for wave in waves:
        waveName = wave["wave"]
        commands = wave["wave_commands"]
        for commName in commands:
            # 2. finding the command only if lvl is port
            comm = mongoInstance.findInDb(pentest, "commands",
                                            {"name": commName, "lvl": "port"}, False)
            if comm is not None:
                # 3. checking if the added port fit into the command's allowed service
                # 3.1 first, default the selected port as tcp if no protocole is defined.
                allowed_ports_services = comm["ports"].split(",")
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
                    if (port_o.proto+"/"+port_o.port == allowed) or \
                    (port_o.proto+"/"+port_o.service == allowed) or \
                    (port_o.proto == protoRange and int(port_o.port) >= int(startAllowedRange) and int(port_o.port) <= int(endAllowedRange)):
                        # finally add tool
                        newTool = ServerTool(pentest)
                        newTool.initialize(
                            comm["name"], waveName, "", port_o.ip, port_o.port, port_o.proto, "port")
                        newTool.addInDb()
    return {"res":True, "iid":iid}

@permission("pentester")
def update(pentest, port_iid, body):
    mongoInstance.connectToDb(pentest)
    
    oldPort = ServerPort(pentest, mongoInstance.find("ports", {"_id": ObjectId(port_iid)}, False))
    if oldPort is None:
        return
    port_o = ServerPort(pentest, body)
    oldService = oldPort.service
    if oldService != port_o.service:
        mongoInstance.delete("tools", {
                                "lvl": "port", "ip": port_o.ip, "port": port_o.port, "proto": port_o.proto}, many=True)
        port_commands = mongoInstance.findInDb(
            pentest, "commands", {"lvl": "port"})
        for port_command in port_commands:
            allowed_services = port_command["ports"].split(",")
            for i, elem in enumerate(allowed_services):
                if not(elem.strip().startswith("tcp/") or elem.strip().startswith("udp/")):
                    allowed_services[i] = "tcp/"+str(elem)
            if port_o.proto+"/"+str(port_o.service) in allowed_services:
                waves = mongoInstance.find("waves", {"wave_commands": {"$elemMatch": {
                    "$eq": port_command["name"].strip()}}})
                for wave in waves:
                    tool_m = ServerTool(pentest).initialize(port_command["name"], wave["wave"], "",
                                                port_o.ip, port_o.port, port_o.proto, "port")
                    tool_m.addInDb()
    return mongoInstance.update("ports", {"_id":ObjectId(port_iid)}, {"$set":body}, False, True)
    
@permission("pentester")
def addCustomTool(pentest, port_iid, body):
    mongoInstance.connectToDb(pentest)
    if not mongoInstance.isUserConnected():
        return "Not connected", 503
    if mongoInstance.find("waves", {"wave": 'Custom Tools'}, False) is None:
        mongoInstance.insert("waves", {"wave": 'Custom Tools', "wave_commands": list()})
    port_o = ServerPort(pentest, mongoInstance.find("ports", {"_id":ObjectId(port_iid)}, False))
    port_o.addAllTool(body["tool_name"], 'Custom Tools', '', check=False)