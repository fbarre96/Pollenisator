import os
import json
from datetime import datetime
from flask import send_file
import core.Reporting.WordExport as WordExport
from core.Components.Utils import loadServerConfig
import core.Reporting.PowerpointExport as PowerpointExport
from server.ServerModels.Defect import ServerDefect
from core.Controllers.DefectController import DefectController
from bson import ObjectId
import requests
from core.Components.mongo import MongoCalendar
from server.permission import permission
dir_path = os.path.dirname(os.path.realpath(__file__))
template_path = os.path.normpath(os.path.join(dir_path, "../Templates/"))
lang_translation = dict()

def validate_lang(lang):
    langs = [existing_lang for existing_lang in os.listdir(template_path) if os.path.isdir(os.path.join(template_path, existing_lang))]
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
    template_to_use_path = os.path.join(template_path, lang+"/",templateName)
    if not os.path.isfile(template_to_use_path):
        return "Template file not found", 404
    outfile = None
    lang_file = os.path.join(template_path,lang+"/lang.json")
    global lang_translation
    with open(lang_file) as f:
        lang_translation = json.loads(f.read())
    defectDict = getDefectsAsDict(pentest)
    if ext == ".docx":
        outfile = WordExport.createReport(pentest, defectDict, getRemarksAsDict(pentest), template_to_use_path, out_name, mainRedac=mainRedactor,
                                client=clientName.strip(), contract=contractName.strip(), translation=lang_translation)
    elif ext == ".pptx":
        outfile = PowerpointExport.createReport(pentest, defectDict, getRemarksAsDict(pentest), template_to_use_path, out_name, client=clientName.strip(), contract=contractName.strip(), translation=lang_translation)
    else:
        return "Unknown template file extension", 400     
    return send_file(outfile, attachment_filename=out_name+ext) 
    

@permission("user")
def search(type, q):
    config = loadServerConfig()
    api_url = config.get('knowledge_api_url', '')
    if api_url == "":
        return "There is no knowledge database implemented.", 503
    try:
        resp = requests.get(api_url, params={"type":type, "terms": q})
    except Exception as e:
        return "The knowledge database is unreachable", 503
    if resp.status_code != 200:
        return "The knowledge dabatase encountered an issue : "+resp.txt, 503
    answer = json.loads(resp.text)
    return answer, 200
    

def getDefectsAsDict(pentest):
    """
    Returns a dictionnary with treeview defects stored inside
    Returns:
        The returned dict will be formed this way (shown as json):
        {
            "Risk level describer 1":{
                "defect title 1": {
                    "description":{
                        "title": "defect title 1",
                        "risk": "Risk level 1",
                        "ease": "Ease of exploitation 1",
                        "impact": "Impact 1",
                        "redactor": "Redactor name",
                        "type": ['D', 'T', ...]
                    },
                    "defects_ids":[
                        id 1,
                        id 2...
                    ]
                },
                "defect title 2":{
                    ...
                }
                ...
            },
            "Risk level describer 2":{
                ...
            }
            ...
        }
    """
    
    defects_dict = dict()
    for level in ["Critical", "Major", "Important", "Minor"]:
        defects_dict[level] = dict()
    defects_obj = ServerDefect.fetchObjects(pentest, {"ip": ""})
    for defect_obj in defects_obj:
        title = defect_obj.title
        defect_recap = dict()
        defect_recap["title"] = title
        defect_recap["risk"] = defect_obj.risk
        defect_recap["ease"] = defect_obj.ease
        defect_recap["impact"] = defect_obj.impact
        defect_recap["redactor"] = defect_obj.redactor
        defect_recap["index"] = defect_obj.index
        types = defect_obj.mtype
        d_types = []
        for d_type in types:
            d_types.append(d_type.strip())
        defect_recap["type"] = d_types
        defects_dict[defect_recap["risk"]][title] = dict()
        defects_dict[defect_recap["risk"]
                        ][title]["description"] = defect_recap
        defects_dict[defect_recap["risk"]][title]["defects_ids"] = []
        defects = ServerDefect.fetchObjects(pentest, {"title": title})
        for defect in defects:
            defects_dict[defect_recap["risk"]
                            ][title]["defects_ids"].append(defect.getId())
    return defects_dict
    

def getRemarksAsDict(pentest):
    remarks = {}
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    ds = mongoInstance.find("remarks", {}, True)
    if ds is None:
        return None
    for d in ds:
        if d["type"] not in remarks:
            remarks[d["type"]] = []
        remarks[d["type"]].append(d["title"])
    return remarks