"""
Handle worker management
"""
import json
from typing import Optional, Tuple, Union, List, Dict, Any, cast
import uuid
import docker
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.socketmanager import SocketManager
from pollenisator.core.models.tool import Tool
from pollenisator.server.servermodels.command import addUserCommandsToPentest
from pollenisator.server.permission import permission
from pollenisator.core.components.logger_config import logger

dbclient = DBClient.getInstance()

ErrorStatus = Tuple[str, int]

@permission("user")
def listWorkers(pipeline: Optional[Union[str, Dict[str, Any]]] = None) -> Union[ErrorStatus, List[Dict[str, Any]]]:
    """
    Return workers documents from the database.

    Args:
        pipeline (Optional[Union[str, Dict[str, Any]]], default=None): The pipeline to use for querying the database.

    Returns:
       Union[ErrorStatus, List[Dict[str, Any]]]: A list of worker documents if successful, otherwise an error message and status code.
    """
    pipeline = {} if pipeline is None else pipeline
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline)
    if pipeline is None or not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    ret = []
    for w in dbclient.getWorkers(pipeline):
        w["_id"] = str(w["_id"])
        ret.append(w)
    return ret

def doSetInclusion(name: str, pentest: str, setInclusionVal: bool) -> bool:
    """
    Set the inclusion of a worker in a pentest.

    Args:
        name (str): The name of the worker.
        pentest (str): The name of the pentest.
        setInclusionVal (bool): Whether to include the worker in the pentest.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    if pentest == "":
        return False
    if setInclusionVal:
        addUserCommandsToPentest(pentest, name)
    return dbclient.setWorkerInclusion(name, pentest, setInclusionVal)

@permission("pentester", "body.db")
def setInclusion(name: str, body: Dict[str, Any], **kwargs: Any) -> bool:
    """
    Set inclusion of a worker in a pentest.

    Args:
        name (str): The name of the worker.
        body (Dict[str, Union[str, bool]]): A dictionary containing the pentest name and whether to include the worker.
            "db" (str): The name of the pentest.
            "setInclusion" (bool): Whether to include the worker in the pentest.
        **kwargs (Any): Additional parameters.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    body_db = body.get("db")
    if body_db is None:
        return False
    return doSetInclusion(name, str(body_db), bool(body.get("setInclusion", False)))


def doDeleteWorker(name: str) -> Union[ErrorStatus, int]:
    """
    Delete a worker from the database.

    Args:
        name (str): The name of the worker to delete.

    Returns:
        Union[ErrorStatus, int]: A success message if the worker was successfully deleted, otherwise an error message and status code.
    """
    res = dbclient.findInDb("pollenisator","workers",{"name":name}, False)
    if res is None:
        return "Worker not found", 404
    socket = dbclient.findInDb("pollenisator", "sockets", {"user":name}, False)
    if socket is not None:
        sm = SocketManager.getInstance()
        sm.socketio.emit('deleteWorker', {'name': name})
    if res.get("container_id") is not None:
        stop_docker(res["container_id"])
    return dbclient.deleteWorker(name)


def removeWorkers() -> Dict[str, int]:
    """
    Remove all workers from the database.

    Returns:
        Dict[str, int]: A dictionary containing the number of workers removed.
    """
    workers = dbclient.getWorkers()
    count = 0
    for worker in workers:
        running_tools = worker.get("running_tools", [])
        for running_tool in running_tools:
            tool_m = Tool.fetchObject(running_tool["pentest"], {"_id":ObjectId(running_tool["iid"])})
            tool_m = cast(Tool, tool_m)
            if "running" in tool_m.getStatus():
                tool_m.markAsNotDone()
                tool_m.update()
        doDeleteWorker(worker["name"])
        count += 1
    return {"n":int(count)}


@permission("user")
def deleteWorker(name: str) -> Union[Tuple[str, int], Dict[str, int]]:
    """
    Delete a worker from the database.

    Args:
        name (str): The name of the worker to delete.

    Returns:
        Union[Tuple[str, int], Dict[str, int]]: A dictionary containing the number of workers deleted if successful, otherwise an error message and status code.
    """
    res = doDeleteWorker(name)
    if isinstance(res, tuple):
        return res
    return {"n":int(res)}

def stop_docker(docker_id: str) -> Union[Tuple[bool, str], None]:
    """
    Stop a running Docker container.

    Args:
        docker_id (str): The ID of the Docker container to stop.

    Returns:
        Union[Tuple[bool, str], None]: A tuple containing False and an error message if unable to stop the Docker container, None otherwise.
    """
    try:
        client = docker.from_env()
        container = client.containers.get(docker_id)
        container.stop()
    except Exception as e:
        return False, "Unable to stop docker "+str(e)
    return True, "Stopped docker"

def start_docker(force_reinstall: bool, docker_id: str) -> Tuple[bool, str]:
    """
    Start a Docker container.

    Args:
        force_reinstall (bool): If True, reinstall the Docker container.
        docker_id (str): The ID of the Docker container to start.

    Returns:
        Tuple[bool, str]: A tuple containing a boolean indicating whether the operation was successful, and a string containing the ID of the started Docker container or an error message.
    """
    try:
        client = docker.from_env()
        clientAPI = docker.APIClient()
    except Exception as e:
        return False, "Unable to launch docker "+str(e)
    try:
        log_generator = clientAPI.pull("algosecure/pollenisator-worker:latest",stream=True,decode=True)
        for byte_log in log_generator:
            log_line = byte_log["status"].strip()
            logger.info(log_line)
    except docker.errors.APIError as e:
        return False, "Pull docker error:\n"+str(e)
    image = client.images.list("algosecure/pollenisator-worker")
    if len(image) == 0:
        return False, "The docker pull command failed, try to install manually..."
    network_mode = "host"
    container = client.containers.run(image=image[0],
                    network_mode=network_mode,
                    environment={"POLLENISATOR_WORKER_NAME":str(docker_id)},
                    detach=True)
    if container.logs() != b"":
        logger.warning(container.logs())
    return True, str(container.id)

@permission("pentester")
def startWorker(pentest: str, **kwargs: Any) -> ErrorStatus:
    """
    Start a worker for a given pentest.

    Args:
        pentest (str): The name of the pentest.
        **kwargs (Any): Additional parameters, including the user token.

    Returns:
        ErrorStatus: The ID of the started worker if successful, otherwise an error message and status code.
    """
    user = kwargs["token_info"]["sub"]
    existing = dbclient.findInDb("pollenisator", "workers", {"pentest": pentest}, False)
    if existing is not None:
        return str(existing["name"]), 200
    docker_id = uuid.uuid4()
    existing = dbclient.insertInDb("pollenisator", "workers", {"pentest": pentest, "name":str(docker_id)}, False, False)
    ret, msg = start_docker(True, docker_id)
    if ret:
        dbclient.updateInDb("pollenisator", "workers", {"pentest": pentest, "name":str(docker_id)}, {"$set":{"container_id":msg}}, False, False)
        return str(docker_id), 200
    return msg, 403

@permission("worker")
def registerWorker(body: Dict[str, Any]) -> Any:
    """
    Register a worker with the given name and command names.

    Args:
        body (Dict[str, Union[str, List[str]]]): A dictionary containing the worker's name and command names.
            "name" (str): The name of the worker.
            "command_names" (List[str]): The list of command names.

    Returns:
        Any: The result of the registration operation.
    """
    name = str(body["name"])
    command_names = body["command_names"]
    if not isinstance(command_names, list):
        return "command_names must be a list", 400
    res = dbclient.registerWorker(name, command_names)
    return res

def unregister(name: str) -> ErrorStatus:
    """
    Unregister a worker with the given name.

    Args:
        name (str): The name of the worker to unregister.

    Returns:
        ErrorStatus: True if the worker was successfully unregistered, otherwise an error message and status code.
    """
    worker = dbclient.getWorker(name)
    if worker is not None:
        running_tools = worker.get("running_tools", [])
        for running_tool in running_tools:
            tool_m = Tool.fetchObject(running_tool["pentest"], {"_id":ObjectId(running_tool["iid"])})
            tool_m = cast(Tool, tool_m)
            if "running" in tool_m.getStatus():
                tool_m.markAsNotDone()
                tool_m.update()
        doDeleteWorker(name)
        return "Success", 200
    return "Worker not Found", 404
