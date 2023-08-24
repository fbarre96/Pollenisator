from pollenisator.core.components.logger_config import logger
import os
from docxtpl import DocxTemplate
from docxtpl import InlineImage
import jinja2
from markdowntodocx.markdownconverter import convertMarkdownInFile
import re
from docx.shared import Cm

def translate(w):
    if isinstance(w, list):
        trads = []
        for x in w:
            trads.append(translation.get(x, x))
        return trads
    return translation.get(w, w)

def getInitials(words):
    initials = []
    if isinstance(words,str):
        words = words.split(",")
    for word in words:
        try:
            word_str = "".join([x[0] for x in word.split(" ")]) # Active Directory -> AD and Base -> B
        except:
            word_str = ""
        initials.append(word_str)
    return ", ".join(initials)


def createReport(context, template, out_name, **kwargs):
    global translation
    translation = kwargs.get("translation")
    global cell_style
    global normal_style
    doc = DocxTemplate(template)
    jinja_env = jinja2.Environment(autoescape=True)
    jinja_env.filters['translate'] = translate
    jinja_env.filters['getInitials'] = getInitials
    for defect in context["defects"]:
        proofs = defect.get("proofs", [])
        proofs_remaining = [x for x in proofs]
        if proofs:
            for i, para in enumerate(defect.get("description_paragraphs", [])):
                re_matches = re.search(r"\[Proof (\d+)\]", para.strip())
                if re_matches is not None:
                    ind = int(re_matches.group(1))
                    if ind < len(proofs):
                        defect["description_paragraphs"][i] = InlineImage(doc, proofs[ind], width=Cm(17))
                        try:
                            proofs_remaining.remove(proofs[ind])
                        except ValueError:
                            pass
        for proof in proofs_remaining:
            defect["description_paragraphs"].append(InlineImage(doc, proof, width=Cm(17)))
        for instance in defect.get("instances", []):
            for i,proof in enumerate(instance.get("proofs", [])):
                instance["proofs"][i] = InlineImage(doc, proof)
    try:
        doc.render(context, jinja_env)
    except jinja2.exceptions.TemplateSyntaxError as e:
        return False, "Error in template syntax : "+str(e)
    dir_path = os.path.dirname(os.path.realpath(__file__))
    out_path = os.path.join(dir_path, "../../exports/", out_name+".docx")
    doc.save(out_path)
    logger.info("Converting Markdown of "+str(out_path))
    result, msg = convertMarkdownInFile(out_path, out_path, {"Header":"Sous-défaut"})
    if not result:
        return False, "Error in Markdown conversion : "+str(msg)
    logger.info("Generated report at "+str(out_path))
    return True, out_path
