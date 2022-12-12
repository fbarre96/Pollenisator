import logging
import os
import json
from datetime import datetime
from flask import send_file
import pollenisator.core.Reporting.WordExport as WordExport
import pollenisator.core.Reporting.PowerpointExport as PowerpointExport
from pollenisator.server.ServerModels.Defect import getGlobalDefects
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Components.Utils import JSONEncoder, loadServerConfig, getMainDir
from pollenisator.server.permission import permission
from multiprocessing import Process, Manager
import re
import requests
from bson import ObjectId

main_dir = getMainDir()
template_path = os.path.normpath(os.path.join(main_dir, "./Templates/"))
lang_translation = dict()


def validate_lang(lang):
    langs = [existing_lang for existing_lang in os.listdir(
        template_path) if os.path.isdir(os.path.join(template_path, existing_lang))]
    return lang in langs


@permission("user")
def getLangList():
    onlyfolders = [f for f in os.listdir(template_path) if not os.path.isfile(
        os.path.join(template_path, f))]
    return onlyfolders


@permission("user")
def getTemplateList(lang):
    if not validate_lang(lang):
        return "There is no existing templates for this lang", 400
    lang = os.path.basename(lang)
    langs_path = os.path.join(template_path, lang)
    onlyfiles = [f for f in os.listdir(langs_path) if os.path.isfile(
        os.path.join(langs_path, f)) and f != "lang.json"]
    return onlyfiles


@permission("user")
def downloadTemplate(lang, templateName):
    global template_path
    fileName = os.path.basename(templateName)
    if not fileName.endswith(".pptx") and not fileName.endswith(".docx"):
        return "A template is either a pptx or a docx document", 400
    lang = os.path.basename(lang)
    if not validate_lang(lang):
        return "There is no existing templates for this lang", 400
    template_to_download_path = os.path.join(template_path, lang+"/"+fileName)
    if not os.path.isfile(template_to_download_path):
        return "Template file not found", 404
    try:
        return send_file(template_to_download_path, attachment_filename=fileName)
    except TypeError as e: # python3.10.6 breaks https://stackoverflow.com/questions/73276384/getting-an-error-attachment-filename-does-not-exist-in-my-docker-environment
        return send_file(template_to_download_path, download_name=fileName)


@permission("user")
def uploadTemplate(upfile, lang):
    global template_path
    fileName = upfile.filename.replace("/", "_")
    if not fileName.endswith(".pptx") and not fileName.endswith(".docx"):
        return "Invalid extension for template, must be pptx or docx", 400
    lang = os.path.basename(lang)
    folder_to_upload_path = os.path.join(template_path, lang+"/")
    os.makedirs(folder_to_upload_path)
    template_to_upload_path = os.path.join(folder_to_upload_path, fileName)
    with open(template_to_upload_path, "wb") as f:
        f.write(upfile.steam.read())
        return "Success"
    return "Failure"


@permission("user")
def generateReport(pentest, templateName, clientName, contractName, mainRedactor, lang):
    if not templateName.endswith(".pptx") and not templateName.endswith(".docx"):
        return "Invalid extension for template, must be pptx or docx", 400
    
    timestr = datetime.now().strftime("%Y%m%d-%H%M%S")
    ext = os.path.splitext(templateName)[-1]
    basename = clientName.strip() + "_"+contractName.strip()
    out_name = str(timestr)+"_"+basename
    templateName = os.path.basename(templateName)
    lang = os.path.basename(lang)
    if not validate_lang(lang):
        return "There is no existing templates for this lang", 400
    template_to_use_path = os.path.join(template_path, lang+"/", templateName)
    if not os.path.isfile(template_to_use_path):
        return "Template file not found", 404
    outfile = None
    lang_file = os.path.join(template_path, lang+"/lang.json")
    global lang_translation
    with open(lang_file) as f:
        lang_translation = json.loads(f.read())
    context = craftContext(pentest, mainRedac=mainRedactor,
                           client=clientName.strip(), contract=contractName.strip())
    manager = Manager()
    return_dict = manager.dict()
    p = Process(target=_generateDoc, args=(ext, context, template_to_use_path, out_name, lang_translation, return_dict))
    p.start()
    p.join()
    if return_dict["res"]:
        try:
            return send_file(return_dict["msg"], attachment_filename=out_name+ext)
        except TypeError as e: # python3.10.6 breaks https://stackoverflow.com/questions/73276384/getting-an-error-attachment-filename-does-not-exist-in-my-docker-environment
            return send_file(return_dict["msg"], download_name=out_name+ext)

        
    else:
        return return_dict["msg"], 400
    

def _generateDoc(ext, context, template_to_use_path, out_name, translation, return_dict):
    if ext == ".docx":
        outfile = WordExport.createReport(
            context, template_to_use_path, out_name, translation=translation)
    elif ext == ".pptx":
        outfile = PowerpointExport.createReport(
            context, template_to_use_path, out_name, translation=translation)
    else:
        return_dict["res"] = False
        return_dict["msg"] = "Unknown template file extension"
    return_dict["res"] = True
    return_dict["msg"] = outfile

@permission("user")
def search(body):
    type = body.get("type", "")
    terms = body.get("terms", "")
    lang = body.get("language", "")
    errors = []
    if type == "remark":
        coll = "remarks"
    elif type == "defect":
        coll = "defects"
    else:
        return "Invalid parameter: type must be either defect or remark.", 400
    mongoInstance = MongoCalendar.getInstance()
    p = {"title":re.compile(terms, re.IGNORECASE)}
    if lang != "":
        p["language"] = lang
    res = mongoInstance.findInDb("pollenisator", coll, p, True)
    ret = []
    for x in res:
        ret.append(x)
    config = loadServerConfig()
    api_url = config.get('knowledge_api_url', '')
    if api_url == "":
        return ret
    try:
        resp = requests.get(api_url, params=body, timeout=3)
        if resp.status_code != 200:
            errors += ["The knowledge dabatase encountered an issue : "+resp.text]
        if not errors:
            answer = json.loads(resp.text)
            ret += answer
    except json.JSONDecodeError as e:
        errors += ["The knowledge database returned invalid json"]
    except Exception as e:
        errors += ["The knowledge database is unreachable"]
    ret = {"errors": errors , "answers":ret}
    return ret, 200

def craftContext(pentest, **kwargs):
    mongoInstance = MongoCalendar.getInstance()
    context = {}
    for k, v in kwargs.items():
        context[k] = v
    date = datetime.now()
    context["year"] = date.strftime("%Y")
    context["month"] = date.strftime("%B").lower()
    context["positive_remarks"] = []
    context["negative_remarks"] = []
    context["neutral_remarks"] = []
    remarks = mongoInstance.findInDb(pentest, "remarks", {}, True)
    for remark in remarks:
        if remark["type"].lower() == "positive":
            context["positive_remarks"].append(remark["description"])
        elif remark["type"].lower() == "negative":
            context["negative_remarks"].append(remark["description"])
        elif remark["type"].lower() == "neutral":
            context["neutral_remarks"].append(remark["description"])
    context["colors"] = {
        "fix": {
            "Easy": "00B0F0",
            "Moderate": "0070C0",
            "Mean": "0070C0",
            "Hard": "002060",
            "Quick Win": "00B0F0",
            "Weak": "00B0F0",
            "Strong": "002060",
        }
    }
    scopes_list = [scope for scope in mongoInstance.findInDb(pentest, "scopes", {}, True)]
    context["scopes"] = scopes_list
    pentesters = mongoInstance.getPentestUsers(pentest)
    context["pentesters"] = []
    for pentesterName in pentesters:
        p = mongoInstance.getUserRecordFromUsername(pentesterName)
        if p is not None:
            context["pentesters"].append(p)
    owner = mongoInstance.getPentestOwner(pentest)
    p = mongoInstance.getUserRecordFromUsername(owner)
    context["owner"] = p if p is not None else None
    ports = mongoInstance.findInDb(pentest, "ports", {}, True)
    ports = [port for port in ports]
    ports.sort(key=lambda x: (x["ip"],int(x["port"])))
    context["ports"] = ports
    defects = getGlobalDefects(pentest)
    completed_defects = []
    completed_fixes = []
    defect_id = 1
    for defect in defects:
        defect_completed = defect
        defect_completed["id"] = str(defect_id)
        proof_path = getProofPath(pentest, str(defect_completed["_id"]))
        global_proofs = []
        for pr in defect_completed["proofs"]:
            global_proofs.append(os.path.join(proof_path, os.path.basename(pr)))
        defect_completed["proofs"] = global_proofs
        defect_completed["description_paragraphs"] = defect_completed["description"].replace("\r","").split("\n\n")
        fix_id = 1
        if len(defect_completed["fixes"]) > 1:
            for fix in defect_completed["fixes"]:
                fix["id"] = str(defect_id)+"."+str(fix_id)
                fix_id += 1
        elif len(defect_completed["fixes"]) == 1:
            defect_completed["fixes"][0]["id"] = str(defect_id)
        else:
            logging.warning("Warning: defect in polymathee with no fix")
        for i, fix in enumerate(defect_completed["fixes"]):
            defect_completed["fixes"][i]["description_paragraphs"] = fix["description"].replace("\r","").split("\n\n")
        completed_fixes += defect_completed["fixes"]
        defect_id += 1
        assignedDefects = mongoInstance.findInDb(pentest, "defects", {"global_defect":ObjectId(defect_completed["_id"])}, True)
        defect_completed["instances"] = []
        for assignedDefect in assignedDefects:
            local_proofs = []
            proof_path = getProofPath(pentest, str(assignedDefect["_id"]))
            for pr in assignedDefect.get("proofs", []):
                local_proofs.append(os.path.join(proof_path, os.path.basename(pr)))
            notes_paragraphs = assignedDefect.get("notes", "").replace("\r", "").split("\n\n")
            assignedDefect["proofs"] = local_proofs
            assignedDefect["notes_paragraphs"] = notes_paragraphs
            defect_completed["instances"].append(assignedDefect)
        completed_defects.append(defect_completed)
    context["defects"] = completed_defects
    context["fixes"] = completed_fixes
    return context

def getProofPath(pentest, defect_iid):
    local_path = os.path.join(getMainDir(), "files")

    return os.path.join(local_path, pentest, "proof", str(defect_iid))

# def getKnownDefectFromKnowledgeDB(defect):
#     mongoInstance = MongoCalendar.getInstance()
#     #result, status = search({"type":"defect", "terms":defect["title"]})
#     if status != 200:
#         result = None
#     impossible_to_connect = False
#     if result is None:
#         impossible_to_connect = True
#     elif isinstance(result, bool):
#         if result == False:
#             impossible_to_connect = True
#     elif len(result) == 0:
#         impossible_to_connect = True
#     if impossible_to_connect:
#         result = [
#             {
#                 "id": "0",
#                 "title": defect["title"],
#                 "ease": defect["ease"],
#                 "impact": defect["impact"],
#                 "risk": defect["risk"],
#                 "type": defect["type"],
#                 "synthesis": "ToDo",
#                 "description": "ToDo",
#                 "redactor": "N/A",
#                 "fixes": [
#                     {
#                         "title": "ToDo",
#                         "execution": "Moderate",
#                         "gain": "Moderate",
#                         "synthesis": "ToDo",
#                         "description": "ToDo",
#                     }
#                 ]
#             }
#         ]

#     result = result[0]
#     if result["description"]:
#         result["description"] = result.get("description", "ToDo").replace(
#             "<", "&lt;").replace(">", "&gt;")
#         result["description_paragraphs"] = result["description"].replace(
#             "\r", "").split("\n\n")
#     if result["synthesis"]:
#         result["synthesis"] = result.get("synthesis", "ToDo").replace(
#             "<", "&lt;").replace(">", "&gt;")
#     for fix in result["fixes"]:
#         if fix["synthesis"]:
#             fix["synthesis"] = fix.get("synthesis", "ToDo").replace(
#                 "<", "&lt;").replace(">", "&gt;")
#         if fix["description"]:
#             fix["description"] = fix.get("description", "ToDo").replace(
#                 "<", "&lt;").replace(">", "&gt;")
#             fix["description_paragraphs"] = fix["description"].replace(
#                 "\r", "").split("\n\n")
#     for key, val in defect.items():
#         if result.get(key, None) is None:
#             result[key] = val

#     result["ease"] = defect["ease"]
#     result["impact"] = defect["impact"]
#     result["risk"] = defect["risk"]
#     return result


# def getKnownRemarkFromKnowledgeDB(remark):
#     result, status = search({"type":"remark", "terms":remark["title"]})
#     if status != 200:
#         result = None
#     impossible_to_connect = False
#     if result is None:
#         impossible_to_connect = True
#     elif isinstance(result, bool):
#         if result == False:
#             impossible_to_connect = True
#     elif len(result) == 0:
#         impossible_to_connect = True
#     if impossible_to_connect:
#         result = [
#             {
#                 "id": None,
#                 "title": remark["title"],
#                 "description": remark["title"],
#                 "type": remark["type"],
#             }
#         ]
#     return result[0]
