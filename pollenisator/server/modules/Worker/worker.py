import json
import logging
import uuid
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Controllers.ToolController import ToolController
from pollenisator.server.ServerModels.Command import addUserCommandsToPentest
from pollenisator.server.ServerModels.CommandGroup import addUserGroupCommandsToPentest
from pollenisator.server.ServerModels.Tool import ServerTool, update as tool_update
from bson import ObjectId
from pollenisator.server.permission import permission
import pollenisator.core.Components.Utils as Utils
import shutil
import os
import docker
try:
    import git
    git_available = True
except:
    git_available = False

mongoInstance = MongoCalendar.getInstance()

@permission("user")
def listWorkers(pipeline=None):
    """Return workers documents from database
    Returns:
        Mongo result of workers. Cursor of dictionnary."""
    pipeline = {} if pipeline is None else pipeline
    pipeline = json.loads(pipeline)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    ret = []
    for w in mongoInstance.getWorkers(pipeline):
        w["_id"] = str(w["_id"])
        ret.append(w)
    return ret

def doSetInclusion(name, user, pentest, setInclusion):
    if name != user: # is Worker
        addUserCommandsToPentest( pentest, "Worker")
        addUserGroupCommandsToPentest( pentest, "Worker")
    return mongoInstance.setWorkerInclusion(name, pentest, setInclusion)

@permission("pentester", "body.db")
def setInclusion(name, body, **kwargs):
    "Set a worker inclusion in a pentest"
    user = kwargs["token_info"]["sub"]
    return doSetInclusion(name, user, body["db"], body["setInclusion"])

def doDeleteWorker(name):
    res = mongoInstance.findInDb("pollenisator","workers",{"name":name}, False)
    if res is None:
        return None
    if res.get("container_id") is not None:
        stop_docker(res["container_id"])
    return mongoInstance.deleteWorker(name)


def removeWorkers():
    mongoInstance = MongoCalendar.getInstance()
    workers = mongoInstance.getWorkers()
    count = 0
    for worker in workers:
        running_tools = worker.get("running_tools", [])
        for running_tool in running_tools:
            tool_m = ServerTool.fetchObject(running_tool["pentest"], {"_id":ObjectId(running_tool["iid"])})
            if "running" in tool_m.getStatus():
                tool_m.markAsNotDone()
                tool_update(running_tool["pentest"], running_tool["iid"], ToolController(tool_m).getData())
        doDeleteWorker(worker["name"])
        count += 1
    return {"n":int(count)}


@permission("user")
def deleteWorker(name):
    res = doDeleteWorker(name)
    if res is None:
        return "Worker not found", 404
    
    return {"n":int(res.deleted_count)}

def stop_docker(docker_id):
    try:
        client = docker.from_env()
        container = client.containers.get(docker_id)
        container.stop()
    except Exception as e:
        return False, "Unable to stop docker "+str(e)

def start_docker(force_reinstall, docker_id):
    worker_subdir = os.path.join(Utils.getMainDir(), "PollenisatorWorker")
    if os.path.isdir(worker_subdir) and force_reinstall:
        git.Git(worker_subdir).pull()
    if not os.path.isdir(worker_subdir):
        git.Git(Utils.getMainDir()).clone("https://github.com/fbarre96/PollenisatorWorker.git")
    try:
        client = docker.from_env()
        clientAPI = docker.APIClient()
    except Exception as e:
        return False, "Unable to launch docker "+str(e)
    try:
        log_generator = clientAPI.pull("algosecure/pollenisator-worker",stream=True,decode=True)
        for byte_log in log_generator:
            log_line = byte_log["status"].strip()
            logging.info(log_line)
    except docker.errors.APIError as e:
        return False, "Pull docker error:\n"+str(e)
    image = client.images.list("algosecure/pollenisator-worker")
    if len(image) == 0:
        return False, "The docker pull command failed, try to install manually..."
    network_mode = "host"
    container = client.containers.run(image=image[0], 
                    network_mode=network_mode,
                    volumes={os.path.join(Utils.getMainDir(), "PollenisatorWorker"):{'bind':'/home/Pollenisator', 'mode':'rw'}},
                    environment={"POLLENISATOR_WORKER_NAME":str(docker_id)},
                    detach=True)
    if container.logs() != b"":
        logging.warning(container.logs())
    return True, str(container.id)

@permission("pentester")
def startWorker(pentest, **kwargs):
    user = kwargs["token_info"]["sub"]
    existing = mongoInstance.findInDb("pollenisator", "workers", {"pentest": pentest}, False)
    if existing is not None:
        return str(existing["name"])
    docker_id = uuid.uuid4()
    existing = mongoInstance.insertInDb("pollenisator", "workers", {"pentest": pentest, "name":str(docker_id)}, False, False)
    ret, msg = start_docker(True, docker_id)
    
    if ret:
        mongoInstance.updateInDb("pollenisator", "workers", {"pentest": pentest, "name":str(docker_id)}, {"$set":{"container_id":msg}}, False, False)
        return str(docker_id)
    return msg, 403

@permission("worker")
def registerWorker(body):
    name = body["name"]
    command_names = body["command_names"]
    res = mongoInstance.registerCommands(name, command_names)
    return res

def unregister(name):
    worker = mongoInstance.getWorker(name)
    if worker is not None:
        running_tools = worker.get("running_tools", [])
        for running_tool in running_tools:
            tool_m = ServerTool.fetchObject(running_tool["pentest"], {"_id":ObjectId(running_tool["iid"])})
            if "running" in tool_m.getStatus():
                tool_m.markAsNotDone()
                tool_update(running_tool["pentest"], running_tool["iid"], ToolController(tool_m).getData())
        doDeleteWorker(name)
        return True
    return "Worker not Found", 404
