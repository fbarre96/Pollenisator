"""worker module. Execute code and store results in database, files in the SFTP server.
"""

import errno
import os
import ssl
import sys
import uuid
import time
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from multiprocessing import Process
from core.Components.apiclient import APIClient
import core.Components.Utils as Utils
from core.Models.Interval import Interval
from core.Models.Tool import Tool
from core.Models.Wave import Wave
from core.Models.Command import Command
from shutil import copyfile
import socket


def main():
    """Main function. Start a worker instance
    """
    apiclient = APIClient.getInstance()
    tools_to_register = Utils.loadToolsConfig()
    print("Registering commands : "+str(list(tools_to_register.keys())))
    myname = str(uuid.uuid4())+"@"+socket.gethostname()
    apiclient.registeredCommands(myname, list(tools_to_register.keys()))
    p = Process(target=workerLoop, args=(myname,))
    try:
        p.start()
        p.join()
    except(KeyboardInterrupt, SystemExit):
        pass

def workerLoop(workerName):
    """
    Start monitoring events
    Will stop when receiving a KeyboardInterrupt
    Args:
        calendar: the pentest database name to monitor
    """
    print("Starting worker thread")
    functions = {
        "executeCommand": executeCommand
    }
    apiclient = APIClient.getInstance()
    try:
        while(True):
            time.sleep(3)
            apiclient.updateWorkerHeartbeat(workerName)
            instructions = apiclient.fetchWorkerInstruction(workerName)
            for instruction in instructions:
                if instruction["function"] in functions:
                    functions[instruction["function"]](*instruction["args"])


    except(KeyboardInterrupt, SystemExit):
        print("stop received...")
        apiclient.unregisterWorker(workerName)

def launchTask(calendarName, worker, launchableTool):
    launchableToolId = launchableTool.getId()
    launchableTool.markAsRunning(worker)
    # Mark the tool as running (scanner_ip is set and dated is set, datef is "None")
    from AutoScanWorker import executeCommand
    print("Launching command "+str(launchableTool))
    p = Process(target=executeCommand, args=(calendarName, launchableToolId))
    p.start()
    # Append to running tasks this  result and the corresponding tool id
    return True


def dispatchLaunchableToolsv2(launchableTools, worker):
    """
    Try to launch given tools within the

    Args:
        launchableTools: A list of tools within a Wave that passed the Intervals checking.
    """
    apiclient = APIClient.getInstance()
    for launchableTool in launchableTools:
        tool = Tool.fetchObject({"_id": ObjectId(launchableTool["_id"])})
        if hasSpaceFor(worker, tool, apiclient.getCurrentPentest()):
            launchTask(apiclient.getCurrentPentest(), launchableTool["_id"], worker)

def findLaunchableToolsOnWorker(workername, calendarName):
    """ 
    Try to find tools that matches all criteria.
    Args:
        workerName: the current working worker
    Returns:
        A tuple with two values:
            * A list of launchable tools as dictionary with values _id, name and priority
            * A dictionary of waiting tools with tool's names as keys and integer as value.
    """
    apiclient = APIClient.getInstance()
    apiclient.setCurrentPentest(calendarName)
    toolsLaunchable = []
    commands_registered = apiclient.getRegisteredCommands(workername)
    
    waiting = {}
    time_compatible_waves_id = Wave.searchForAddressCompatibleWithTime()
    for wave_id in time_compatible_waves_id:
        commandsLaunchableWave = Wave.getNotDoneTools(wave_id)
        for tool in commandsLaunchableWave:
            
            toolModel = Tool.fetchObject({"_id": tool})
            if toolModel.name not in commands_registered:
                continue
            if hasRegistered(workername, toolModel):
                
                try:
                    waiting[str(toolModel)] += 1
                except KeyError:
                    waiting[str(toolModel)] = 1
                command = toolModel.getCommand()
                if command is None:
                    prio = 0
                else:
                    prio = int(command.get("priority", 0))
                toolsLaunchable.append(
                    {"_id": tool, "name": str(toolModel), "priority": prio, "errored": "error" in toolModel.status})

    return toolsLaunchable, waiting



#@app.task
def getCommands(calendarName, worker_name):
    """
     remote task
    List worker registered tools in configuration folder.
    Store the results in mongo database in pollenisator.workers database.
    """
    apiclient = APIClient.getInstance()
    apiclient.setCurrentPentest(calendarName)
    tools_to_register = Utils.loadToolsConfig()
    print("Registering commands : "+str(list(tools_to_register.keys())))
    apiclient.registeredCommands(worker_name, list(tools_to_register.keys()))
    return


#@app.task
def startAutoScan(calendarName, workerName):
    apiclient = APIClient.getInstance()
    apiclient.setCurrentPentest(calendarName)
    print("Starting auto scan on "+str(calendarName))
    autoScanv2(calendarName, workerName)
    return

#@app.task
def editToolConfig(command_name, remote_bin, plugin):
    tools_to_register = Utils.loadToolsConfig()
    tools_to_register[command_name] = {"bin":remote_bin, "plugin":plugin}
    Utils.saveToolsConfig(tools_to_register)

def autoScanv2(databaseName, workerName):
    """
    Search tools to launch within defined conditions and attempts to launch them this  worker.
    Gives a visual feedback on stdout

    Args:
        databaseName: The database to search tools in
        endless: a boolean that indicates if the autoscan will be endless or if it will stop at the moment it does not found anymore launchable tools.
        useReprinter: a boolean that indicates if the array outpur will be entirely reprinted or if it will be overwritten.
    """
    apiclient = APIClient.getInstance()
    apiclient.setCurrentPentest(databaseName)
    time_compatible_waves_id = Wave.searchForAddressCompatibleWithTime()
    while True:
        # Extract commands with compatible time and not yet done
        launchableTools, waiting = findLaunchableToolsOnWorker(workerName, databaseName)
        # Sort by command priority
        launchableTools.sort(key=lambda tup: (tup["errored"], int(tup["priority"])))
        # print(str(launchableTools))
        dispatchLaunchableToolsv2(launchableTools, workerName)
        
        time.sleep(3)

def executeCommand(calendarName, toolId, parser=""):
    """
     remote task
    Execute the tool with the given toolId on the given calendar name.
    Then execute the plugin corresponding.
    Any unhandled exception will result in a task-failed event in the class.

    Args:
        calendarName: The calendar to search the given tool id for.
        toolId: the mongo Object id corresponding to the tool to execute.
        parser: plugin name to execute. If empty, the plugin specified in tools.d will be feteched.
    Raises:
        Terminated: if the task gets terminated
        OSError: if the output directory cannot be created (not if it already exists)
        Exception: if an exception unhandled occurs during the bash command execution.
        Exception: if a plugin considered a failure.
    """
    # Connect to given calendar
    apiclient = APIClient.getInstance()
    apiclient.setCurrentPentest(calendarName)
    toolModel = Tool.fetchObject({"_id":ObjectId(toolId)})
    command_o = toolModel.getCommand()
    msg = ""
    ##
    success, comm, fileext = apiclient.getCommandline(toolId, parser)
    if not success:
        raise Exception(comm)
    outputRelDir = toolModel.getOutputDir(calendarName)
    abs_path = os.path.dirname(os.path.abspath(__file__))
    toolFileName = toolModel.name+"_" + \
            str(time.time()) # ext already added in command
    outputDir = os.path.join(abs_path, "./results", outputRelDir)
    
    # Create the output directory
    try:
        os.makedirs(outputDir)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(outputDir):
            pass
        else:
            raise exc
    outputDir = os.path.join(outputDir, toolFileName)
    comm = comm.replace("|outputDir|", outputDir)
    # Get tool's wave time limit searching the wave intervals
    if toolModel.wave == "Custom commands":
        timeLimit = None
    else:
        timeLimit = getWaveTimeLimit(toolModel.wave)
    # adjust timeLimit if the command has a lower timeout
    if command_o is not None:
        timeLimit = min(datetime.now()+timedelta(0, int(command_o.get("timeout", 0))), timeLimit)
    ##
    try:
        print(('TASK STARTED:'+toolModel.name))
        print("Will timeout at "+str(timeLimit))
        # Execute the command with a timeout
        returncode = Utils.execute(comm, timeLimit, True)
    except Exception as e:
        raise e
    # Execute found plugin if there is one
    outputfile = outputDir+fileext
    msg = apiclient.importToolResult(toolId, parser, outputfile, returncode)
    if msg != "Success":
        toolModel.markAsNotDone()
        raise Exception(msg)
          
    # Delay
    if command_o is not None:
        if float(command_o.get("sleep_between", 0)) > 0.0:
            msg += " (will sleep for " + \
                str(float(command_o.get("sleep_between", 0)))+")"
        print(msg)
        time.sleep(float(command_o.get("sleep_between", 0)))
    return
    
def getWaveTimeLimit(waveName):
    """
    Return the latest time limit in which this tool fits. The tool should timeout after that limit

    Returns:
        Return the latest time limit in which this tool fits.
    """
    intervals = Interval.fetchObjects({"wave": waveName})
    furthestTimeLimit = datetime.now()
    for intervalModel in intervals:
        if Utils.fitNowTime(intervalModel.dated, intervalModel.datef):
            endingDate = intervalModel.getEndingDate()
            if endingDate is not None:
                if endingDate > furthestTimeLimit:
                    furthestTimeLimit = endingDate
    return furthestTimeLimit

if __name__ == '__main__':
    main()
