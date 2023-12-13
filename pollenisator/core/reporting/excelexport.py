# from pollenisator.core.components.logger_config import logger
# from xlsxtpl.writerx import BookWriter
# from PIL import Image
# import re
# import os
# import jinja2

# def translate(w):
#     if isinstance(w, list):
#         trads = []
#         for x in w:
#             trads.append(translation.get(x, x))
#         return trads
#     return translation.get(w, w)

# def getInitials(words):
#     initials = []
#     if isinstance(words,str):
#         words = words.split(",")
#     for word in words:
#         try:
#             word_str = "".join([x[0] for x in word.split(" ")]) # Active Directory -> AD and Base -> B
#         except:
#             word_str = ""
#         initials.append(word_str)
#     return ", ".join(initials)


# def createReport(context, template, out_name, **kwargs):
#     global translation
#     translation = kwargs.get("translation")
#     writer = BookWriter(template)
#     jinja_env = jinja2.Environment(autoescape=True)
#     writer.jinja_env.globals.update(dir=dir, getattr=getattr, getInitials=getInitials, translate=translate)

#     for defect in context["defects"]:
#         proofs = defect.get("proofs", [])
#         proofs_remaining = [x for x in proofs]
#         if proofs:
#             for i, para in enumerate(defect.get("description_paragraphs", [])):
#                 re_matches = re.search(r"\[Proof (\d+)\]", para.strip())
#                 if re_matches is not None:
#                     ind = int(re_matches.group(1))
#                     if ind < len(proofs):
#                         defect["description_paragraphs"][i] = Image.open(proofs[ind])
#                         try:
#                             proofs_remaining.remove(proofs[ind])
#                         except ValueError:
#                             pass
#         for proof in proofs_remaining:
#             defect["description_paragraphs"].append(Image.open(proof))
#         for instance in defect.get("instances", []):
#             for i,proof in enumerate(instance.get("proofs", [])):
#                 instance["proofs"][i] = Image.open(proof)
    
#     context["sheet_name"] = "Worksheet 1"
#     payloads = [context]
#     writer.render_sheets(payloads=payloads)
#     dir_path = os.path.dirname(os.path.realpath(__file__))
#     out_path = os.path.join(dir_path, "../../exports/", out_name+".xlsx")
#     writer.save(out_path)
#     writer.close()
 
#     logger.info("Generated report at "+str(out_path))
#     return True, out_path
