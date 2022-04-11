import json
import logging
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
import logging
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

@permission("pentester", "body.db")
def setInclusion(name, body, **kwargs):
    "Set a worker inclusion in a pentest"
    user = kwargs["token_info"]["sub"]
    if name != user: # is Worker
        addUserCommandsToPentest( body["db"], "Worker")
        addUserGroupCommandsToPentest( body["db"], "Worker")
    return mongoInstance.setWorkerInclusion(name, body["db"], body["setInclusion"])

@permission("user")
def deleteWorker(name):
    res = mongoInstance.deleteWorker(name)
    if res is None:
        return "Worker not found", 404
    
    return {"n":int(res.deleted_count)}

def removeWorkers():
    workers = mongoInstance.getWorkers()
    count = 0
    for worker in workers:
        running_tools = worker.get("running_tools", [])
        for running_tool in running_tools:
            tool_m = ServerTool.fetchObject(running_tool["pentest"], {"_id":ObjectId(running_tool["iid"])})
            if "running" in tool_m.getStatus():
                tool_m.markAsNotDone()
                tool_update(running_tool["pentest"], running_tool["iid"], ToolController(tool_m).getData())
        deleteWorker(worker["name"])
        count += 1
    return {"n":int(count)}


def start_docker(force_reinstall):
    worker_subdir = os.path.join(Utils.getMainDir(), "PollenisatorWorker")
    if os.path.isdir(worker_subdir) and force_reinstall:
        shutil.rmtree(worker_subdir)
    if not os.path.isdir(worker_subdir):
        git.Git(Utils.getMainDir()).clone("https://github.com/fbarre96/PollenisatorWorker.git")
    try:
        client = docker.from_env()
        clientAPI = docker.APIClient()
    except Exception as e:
        return False, "Unable to launch docker "+str(e)
    image = client.images.list("pollenisatorworker")
    if len(image) == 0 or force_reinstall:
        try:
            log_generator = clientAPI.build(path=os.path.join(Utils.getMainDir(), "PollenisatorWorker/"), rm=True, tag="pollenisatorworker", nocache=force_reinstall)
            for byte_log in log_generator:
                log_line = byte_log.decode("utf-8").strip()
                if log_line.startswith("{\"stream\":\""):
                    log_line = log_line[len("{\"stream\":\""):-4]
                    logging.info(log_line)
        except docker.errors.BuildError as e:
            return False, "Build docker error:\n"+str(e)
        image = client.images.list("pollenisatorworker")
    if len(image) == 0:
        return False, "The docker build command failed, try to install manually..."
    network_mode = "host"
    container = client.containers.run(image=image[0], network_mode=network_mode, volumes={os.path.join(Utils.getMainDir(), "PollenisatorWorker"):{'bind':'/home/Pollenisator', 'mode':'rw'}}, detach=True)
    if container.logs() != b"":
        logging.warning(container.logs())
    return True, str(container.id)

@permission("pentester")
def startWorker(pentest, **kwargs):
    user = kwargs["token_info"]["sub"]
    existing = mongoInstance.findInDb(pentest, "workers", {"pentests": pentest}, False)
    if existing is not None:
        return str(existing["_id"])
    ret, msg = start_docker(False)
    if ret:
        return msg
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
        mongoInstance.deleteFromDb("pollenisator", "workers", {"name": name}, False, True)
        return True
    return "Worker not Found", 404
