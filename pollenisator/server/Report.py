import logging
import os
import json
from datetime import datetime
from flask import send_file
import pollenisator.core.Reporting.WordExport as WordExport
import pollenisator.core.Reporting.PowerpointExport as PowerpointExport
from pollenisator.server.ServerModels.Defect import getGlobalDefects
from pollenisator.server.FileManager import getProofPath
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Components.Utils import JSONEncoder
from pollenisator.server.permission import permission
import re
from bson import ObjectId

dir_path = os.path.dirname(os.path.realpath(__file__))
template_path = os.path.normpath(os.path.join(dir_path, "../Templates/"))
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
    return send_file(template_to_download_path, attachment_filename=fileName)


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
    if ext == ".docx":
        outfile = WordExport.createReport(
            context, template_to_use_path, out_name, translation=lang_translation)
    elif ext == ".pptx":
        outfile = PowerpointExport.createReport(
            context, template_to_use_path, out_name, translation=lang_translation)
    else:
        return "Unknown template file extension", 400
    return send_file(outfile, attachment_filename=out_name+ext)


@permission("user")
def search(body):
    type = body.get("type", "")
    terms = body.get("terms", "")
    lang = body.get("language", "")
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
    return ret


def craftContext(pentest, **kwargs):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    context = {}
    for k, v in kwargs.items():
        context[k] = v
    date = datetime.now()
    context["year"] = date.strftime("%Y")
    context["month"] = date.strftime("%B").lower()
    context["positive_remarks"] = []
    context["negative_remarks"] = []
    context["neutral_remarks"] = []
    remarks = mongoInstance.find("remarks", {}, True)
    for remark in remarks:
        if remarks["type"].lower() == "positive":
            context["positive_remarks"].append(remarks["title"])
        elif remarks["type"].lower() == "negative":
            context["negative_remarks"].append(remarks["title"])
        elif remarks["type"].lower() == "neutral":
            context["neutral_remarks"].append(remarks["title"])
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
    scopes_list = [scope for scope in mongoInstance.find("scopes", {}, True)]
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
    ports = mongoInstance.find("ports", {}, True)
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
        assignedDefects = mongoInstance.find("defects", {"global_defect":ObjectId(defect_completed["_id"])}, True)
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
