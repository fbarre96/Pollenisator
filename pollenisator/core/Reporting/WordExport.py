import logging
from docx import Document
import os
from docxtpl import DocxTemplate
import jinja2
from markdowntodocx.markdownconverter import convertMarkdownInFile
    
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
    jinja_env = jinja2.Environment()
    jinja_env.filters['translate'] = translate
    jinja_env.filters['getInitials'] = getInitials
    doc.render(context, jinja_env)
    dir_path = os.path.dirname(os.path.realpath(__file__))
    out_path = os.path.join(dir_path, "../../exports/", out_name+".docx")
    doc.save(out_path)
    logging.info("Converting Markdown ...")
    convertMarkdownInFile(out_path, out_path, {"Header":"Sous-défaut"})
    logging.info("Generated report at "+str(out_path))
    return out_path
