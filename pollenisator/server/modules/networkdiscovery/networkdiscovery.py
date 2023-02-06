from pollenisator.server.permission import permission
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.servermodels.command import ServerCommand
from pollenisator.server.servermodels.scope import ServerScope
#from pollenisator.server.servermodels.tool import ServerTool, delete as tool_delete
from bson import ObjectId   
import ipaddress
from netaddr import IPNetwork


coll_name = "NetworkDiscovery"
COMMONS = ["10.0.0.0/24","10.10.0.0/24", "10.10.10.0/24"]


@permission("pentester")
def addRangeMatchingIps(pentest):
    dbclient = DBClient.getInstance()
    #dbclient.find("settings", {"key":"network_discovery_"})
    ips = dbclient.findInDb(pentest, "ips", {})
    if ips is None:
        ips = []
    networks = set()
    for ip in ips:
        networks.add(str(ipaddress.IPv4Network(f'{ip.ip}/255.255.255.0', strict=False)))
    if networks:
        wave = dbclient.findInDb(pentest, "waves", {"wave":{"$ne":"Imported"}}, False)
        for net in networks:
            ServerScope(pentest).initialize(wave["wave"], scope=str(net)).addInDb()
            #insertNetwork(pentest, net)
    return "OK"

@permission("pentester")
def addRangeCloseToOthers(pentest):
    dbclient = DBClient.getInstance()
    #dbclient.find("settings", {"key":"network_discovery_"})
    wave = dbclient.findInDb(pentest, "waves", {"wave":{"$ne":"Imported"}}, False)
    real_networks = dbclient.aggregateFromDb(pentest, "ips", [
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
        scope_d = dbclient.findInDb(pentest, "scopes", {"_id":ObjectId(real_network["_id"]["in_scopes"])}, False)
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
    dbclient = DBClient.getInstance()
    wave = dbclient.findInDb(pentest, "waves", {"wave":{"$ne":"Imported"}}, False)
    for common in COMMONS:
        ServerScope(pentest).initialize(wave["wave"], scope=str(common)).addInDb()
    return "OK"

@permission("pentester")
def addAllLANRanges(pentest):
    dbclient = DBClient.getInstance()
    wave = dbclient.findInDb(pentest, "waves", {"wave":{"$ne":"Imported"}}, False)
    net = IPNetwork("10.0.0.0/8")
    subnets = list(net.subnet(16))
    net = IPNetwork("192.168.0.0/16")
    subnets += list(net.subnet(16))
    net = IPNetwork("172.16.0.0/12")
    subnets += list(net.subnet(16))
    for subnet in subnets:
        ServerScope(pentest).initialize(wave["wave"], scope=str(subnet)).addInDb()
    return "OK"

