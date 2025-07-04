
from datetime import datetime
from typing import Any, Dict
import pollenisator.core.components.utils as utils
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.interval import Interval
from pollenisator.server.permission import permission


def getGlobalEvaluations(pentests):
    """
    Get global evaluations
    """
    global_evaluations = {}
    risks = ["Critical", "Major", "Moderate", "Minor"]
    dbclient = DBClient.getInstance()
    for pentest in pentests:
        defects = dbclient.findInDb(pentest, "defects", {"target_id":None}, True, use_cache=False)
        pentest_points = 0
        for defect in defects:
            if defect["risk"] not in risks:
                continue
            if defect["risk"] == "Critical":
                pentest_points += 5
            elif defect["risk"] == "Major":
                pentest_points += 4
            elif defect["risk"] == "Important":
                pentest_points += 1
            elif defect["risk"] == "Minor":
                pentest_points += 0.5
        if pentest_points >= 10:
            global_evaluations["Critical"] = global_evaluations.get("Critical", 0) + 1
        elif pentest_points >= 5:
            global_evaluations["Major"] = global_evaluations.get("Major", 0) + 1
        elif pentest_points >= 2:
            global_evaluations["Important"] = global_evaluations.get("Important", 0) + 1
        elif pentest_points >= 1:
            global_evaluations["Minor"] = global_evaluations.get("Minor", 0) + 1
            
            
    return global_evaluations

def getGlobalEvaluationsPercentage(global_evaluations):
    """
    Get global evaluations percentage
    """
    global_evaluations_percentage = {}
    total = sum(global_evaluations.values())
    for key, value in global_evaluations.items():
        global_evaluations_percentage[key] = value / total * 100
    return global_evaluations_percentage

def getTopVulns(pentests, top=10):
    """
    Get top vulns
    """
    dbclient = DBClient.getInstance()
    count_defects = {}
    for pentest in pentests:
        defects = dbclient.findInDb(pentest, "defects", {"target_id":None}, True, use_cache=False)
        if defects:
            for defect in defects:
                if defect["title"] in count_defects:
                    count_defects[defect["title"]] += 1
                else:
                    count_defects[defect["title"]] = 1
    top_vulns = []
    i = 0
    for key, value in sorted(count_defects.items(), key=lambda item: item[1], reverse=True):
        top_vulns.append({"title"  : key, "count" : value})
        i+=1
        if i == top:
            break
    return top_vulns

def getAvgDefectRisk(pentests):
    """
    get the average number of defects per risk level
    """
    dbclient = DBClient.getInstance()
    count_defects = {}
    for pentest in pentests:
        defects = dbclient.findInDb(pentest, "defects", {"target_id":None}, True, use_cache=False)
        if defects:
            for defect in defects:
                if defect["risk"] in count_defects:
                    count_defects[defect["risk"]] += 1
                else:
                    count_defects[defect["risk"]] = 1
    total = sum(count_defects.values())
    avg_defect_risk = {}
    for key, value in count_defects.items():
        avg_defect_risk[key] = value / total * 100
    return avg_defect_risk


@permission("user")
def getStatistics(body: Dict[str, Any], **kwargs):
    """
    Get statistics
    """
    start_date = body.get("start_date", None)
    end_date = body.get("end_date", None)
    start_duration = body.get("start_duration", None)
    end_duration = body.get("end_duration", None)
    pentest_types = body.get("pentest_types", None)
    context_lvl = body.get("context", None)
    try:
       start_date = datetime(1970,1,1) if (start_date == "" or start_date is None) else datetime.strptime(start_date, "%d/%m/%Y")
    except ValueError:
        return "Invalid start_date", 400
    try:
        end_date = datetime.now() if (end_date == "" or end_date is None) else datetime.strptime(end_date, "%d/%m/%Y")
    except ValueError:
        return "Invalid end_date", 400
    if start_date > end_date:
        return "start_date must be before end_date", 400
    if pentest_types is not None:
        if not isinstance(pentest_types, list):
            return "pentest_types must be a list", 400
    pentest_types = [ptype.lower() for ptype in pentest_types] if pentest_types is not None else []
        
    start_duration = 0 if start_duration is None else int(start_duration)
    end_duration = 99999999 if end_duration is None else int(end_duration)
    context_lvl = -1 if context_lvl is None else int(context_lvl)
    dbclient = DBClient.getInstance()
    pentests = [pentest for pentest in dbclient.findInDb("pollenisator", "pentests", {"creation_date":{"$gte":start_date,"$lt":end_date} }, True, use_cache=False)]
    if pentests is None or len(pentests) <= 0:
        return "No pentests found", 404 
    filtered_pentests = []
    for pentest in pentests:
        if pentest_types is not None:
            pentest_type_setting = dbclient.findInDb(pentest["uuid"], "settings", {"key": "pentest_type"}, False)
            if pentest_type_setting is not None:
                if pentest_type_setting.get("value", "").lower() not in pentest_types:
                    continue
        
        intervals = Interval.fetchObjects(pentest["uuid"], {})
        duration = 0
        for interval in intervals:
            if interval is not None:
                dated = interval.getStartDate()
                datef = interval.getEndingDate()
                if dated is None or datef is None:
                    continue
                duration += (datef - dated).days
        if duration >= start_duration and duration <= end_duration:
            filtered_pentests.append(pentest["uuid"])

    if len(filtered_pentests) <= 0:
        return "No pentests found matching your criterion", 404
    stats = {}
    stats["global_evaluations"] = getGlobalEvaluations(filtered_pentests)
    stats["global_evaluations_percentage"] = getGlobalEvaluationsPercentage(stats["global_evaluations"])
    stats["top_vulns"] = getTopVulns(filtered_pentests)
    stats["average_defect_risk"] = getAvgDefectRisk(filtered_pentests)
    return stats
