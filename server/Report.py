import os
from datetime import datetime
from flask import send_file
import core.Reporting.WordExport as WordExport
import core.Reporting.PowerpointExport as PowerpointExport
from server.ServerModels.Defect import ServerDefect
from core.Controllers.DefectController import DefectController
from bson import ObjectId

dir_path = os.path.dirname(os.path.realpath(__file__))
template_path = os.path.normpath(os.path.join(dir_path, "../Templates/"))


def getTemplateList():
    onlyfiles = [f for f in os.listdir(template_path) if os.path.isfile(
        os.path.join(template_path, f))]
    return onlyfiles


def downloadTemplate(templateName):
    global template_path
    fileName = os.path.basename(templateName)
    if not fileName.endswith(".pptx") and not fileName.endswith(".docx"):
        return "A template is either a pptx or a docx document", 400
    template_to_download_path = os.path.join(template_path, fileName)
    if not os.path.isfile(template_to_download_path):
        return "Template file not found", 404
    return send_file(template_to_download_path, attachment_filename=fileName)


def uploadTemplate(upfile):
    global template_path
    fileName = upfile.filename.replace("/", "_")
    if not fileName.endswith(".pptx") and not fileName.endswith(".docx"):
        return "Invalid extension for template, must be pptx or docx", 400
    template_to_upload_path = os.path.join(template_path, fileName)
    with open(template_to_upload_path, "wb") as f:
        f.write(upfile.steam.read())
        return "Success"
    return "Failure"


def generateReport(pentest, templateName, clientName, contractName, mainRedactor):
    if not templateName.endswith(".pptx") and not templateName.endswith(".docx"):
        return "Invalid extension for template, must be pptx or docx", 400
    timestr = datetime.now().strftime("%Y%m%d-%H%M%S")
    ext = os.path.splitext(templateName)[-1]
    basename = clientName.strip() + "_"+contractName.strip()
    out_name = str(timestr)+"_"+basename
    templateName = os.path.basename(templateName)
    template_to_use_path = os.path.join(template_path, templateName)
    outfile = None
    if ext == ".docx":
        outfile = WordExport.createReport(pentest, getDefectsAsDict(pentest), template_to_use_path, out_name, mainRedac=mainRedactor,
                                client=clientName.strip(), contract=contractName.strip())
    elif ext == ".pptx":
        outfile = PowerpointExport.createReport(pentest, getDefectsAsDict(
        pentest), template_to_use_path, out_name, client=clientName.strip(), contract=contractName.strip())
    else:
        return "Unknown template file extension", 400
    return send_file(outfile, attachment_filename=out_name+ext) 

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
    defects_dict["Critique"] = dict()
    defects_dict["Majeur"] = dict()
    defects_dict["Important"] = dict()
    defects_dict["Mineur"] = dict()
    defects_obj = ServerDefect.fetchObjects(pentest, {"ip": ""})
    for defect_obj in defects_obj:
        title = defect_obj.title
        defect_recap = dict()
        defect_recap["title"] = title
        defect_recap["risk"] = defect_obj.risk
        defect_recap["ease"] = defect_obj.ease
        defect_recap["impact"] = defect_obj.impact
        defect_recap["redactor"] = defect_obj.redactor
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
