from pollenisator.server.permission import permission
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.server.ServerModels.Command import ServerCommand
from pollenisator.server.ServerModels.Scope import ServerScope
from pollenisator.server.ServerModels.Tool import ServerTool, delete as tool_delete
from bson import ObjectId   
import ipaddress
from netaddr import IPNetwork


coll_name = "NetworkDiscovery"
COMMONS = ["10.0.0.0/24","10.10.0.0/24", "10.10.10.0/24"]

@permission("user")
def getModuleInfo():
    return {"registerLvls": []}

# @permission("pentester")
# def insertNetwork(pentest, body):
#     mongoInstance = MongoCalendar.getInstance()
#     mongoInstance.connectToDb(pentest)
#     network = body.get("network", "")
#     # detect overlap
#     networks = [ipaddress.IPv4Network(x["network"]) for x in mongoInstance.find("NetworkDiscovery", {"type":"network"}) if x is not None] 
#     networks_list = sorted(networks)
#     insert_network = ipaddress.IPv4Network(network)
#     for current_network in networks_list:
#         if current_network.overlaps(insert_network):
#             return f"{current_network} overlaps {insert_network}", 200
#     #get host count
#     ips = mongoInstance.find("ips", {})
#     ips = [] if ips is None else ips
#     count = 0
#     for ip in ips:
#         ip_addr = ipaddress.IPv4Address(ip["ip"])
#         address_in_network = ip_addr in insert_network
#         if address_in_network:
#             count += 1
#     #insert
#     ins_result = mongoInstance.insert("NetworkDiscovery", {"type":"network", "network":network, "hostCount":count})
#     insertTools(pentest, network)
#     return {"iid": ins_result.inserted_id, "res": True}

# def insertTools(pentest, net):
#     mongoInstance = MongoCalendar.getInstance()
#     wave_d = mongoInstance.find("waves", {"wave":{"$ne":"Imported"}}, False)
#     commands = ServerCommand.fetchObjects({"lvl":"NetworkDiscovery"}, targetdb=pentest)
#     for command in commands:
#         newTool = ServerTool(pentest)
#         newTool.initialize(command.getId(), wave=wave_d["wave"], scope=net,
#                         lvl="NetworkDiscovery", infos={"network":net})
#         newTool.addInDb(base={"lvl":"NetworkDiscovery", "infos.network":net})


# @permission("pentester")
# def deleteNetwork(pentest, network_iid):
#     mongoInstance = MongoCalendar.getInstance()
#     mongoInstance.connectToDb(pentest)
#     network_dic = mongoInstance.find("NetworkDiscovery", {"_id":ObjectId(network_iid)}, False)
#     if network_dic is None:
#         return 0
#     tools = mongoInstance.find("tools",
#                                 {"lvl": "NetworkDiscovery", "infos.network":network_dic["network"]}, True)
#     for tool in tools:
#         tool_delete(pentest, tool["_id"])
   
#     res = mongoInstance.delete("NetworkDiscovery", {"_id": ObjectId(network_iid)}, False)
#     if res is None:
#         return 0
#     else:
#         return res.deleted_count

@permission("pentester")
def addRangeMatchingIps(pentest):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    #mongoInstance.find("settings", {"key":"network_discovery_"})
    ips = mongoInstance.find("ips", {})
    if ips is None:
        ips = []
    networks = set()
    for ip in ips:
        networks.add(str(ipaddress.IPv4Network(f'{ip.ip}/255.255.255.0', strict=False)))
    if networks:
        wave = mongoInstance.find("waves", {"wave":{"$ne":"Imported"}}, False)
        for net in networks:
            ServerScope(pentest).initialize(wave["wave"], scope=str(net)).addInDb()
            #insertNetwork(pentest, net)
    return "OK"

@permission("pentester")
def addRangeCloseToOthers(pentest):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    #mongoInstance.find("settings", {"key":"network_discovery_"})
    wave = mongoInstance.find("waves", {"wave":{"$ne":"Imported"}}, False)
    real_networks = mongoInstance.aggregate("ips", [
        {
            '$unwind': {
                'path': '$in_scopes', 
                'preserveNullAndEmptyArrays': False
            }
        }, {
            '$group': {
                '_id': {
                    'in_scopes': '$in_scopes'
                }
            }
        }
    ])
    for real_network in real_networks:
        scope_d = mongoInstance.find("scopes", {"_id":ObjectId(real_network["_id"]["in_scopes"])}, False)
        try:
            net = IPNetwork(scope_d["scope"])
        except:
            continue
        prev = str(net.previous())
        next = str(net.next())
        ServerScope(pentest).initialize(wave["wave"], scope=str(prev)).addInDb()
        ServerScope(pentest).initialize(wave["wave"], scope=str(next)).addInDb()
    return "OK"

@permission("pentester")
def addCommonRanges(pentest):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    wave = mongoInstance.find("waves", {"wave":{"$ne":"Imported"}}, False)
    for common in COMMONS:
        ServerScope(pentest).initialize(wave["wave"], scope=str(common)).addInDb()
    return "OK"

@permission("pentester")
def addAllLANRanges(pentest):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    wave = mongoInstance.find("waves", {"wave":{"$ne":"Imported"}}, False)
    net = IPNetwork("10.0.0.0/8")
    subnets = list(net.subnet(16))
    net = IPNetwork("192.168.0.0/16")
    subnets += list(net.subnet(16))
    net = IPNetwork("172.16.0.0/12")
    subnets += list(net.subnet(16))
    for subnet in subnets:
        ServerScope(pentest).initialize(wave["wave"], scope=str(subnet)).addInDb()
    return "OK"

# def handleNotif(pentest, coll, ip, action):
#     if coll == "ips" and action == "insert":
#         ip_addr = ipaddress.IPv4Address(ip)
#         mongoInstance = MongoCalendar.getInstance()
#         mongoInstance.connectToDb(pentest)
#         networks = mongoInstance.find("NetworkDiscovery", {"type":"network"}, True)
#         networks = [] if networks is None else networks
#         for network in networks:
#             if ip_addr in ipaddress.IPv4Network(network["network"]):
#                 mongoInstance.update("NetworkDiscovery", {"_id": ObjectId(network["_id"])}, {"$set":{"hostCount": int(network["hostCount"])+1}})