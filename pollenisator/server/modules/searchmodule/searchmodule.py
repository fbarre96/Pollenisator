"""
Universal search module for searching across multiple pentest data types.
Provides comprehensive search functionality across hosts, ports, checkinstances, terminalsessions with full-text search.
"""

from typing import Any, Dict, List, Union, Tuple, Optional, cast
from bson import ObjectId
import re
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.element import Element
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
from pollenisator.server.permission import permission
from pollenisator.core.components.logger_config import logger

ErrorStatus = Tuple[str, int]

def create_text_indexes(pentest: str) -> None:
    """
    Create text indexes for search functionality.
    
    Args:
        pentest (str): The pentest database name
    """
    dbclient = DBClient.getInstance()
    
    try:
        # Text index for hosts (ips collection)
        dbclient.create_index(pentest, "scopes", [
            ("scope", "text"),
            ("notes", "text")
        ])

        dbclient.create_index(pentest, "ips", [
            ("ip", "text"),
            ("infos.hostname", "text"), 
            ("notes", "text"),
            ("infos.os", "text")
        ])

        dbclient.create_index(pentest, "ports", [
            ("port", "text"),
            ("ip", "text"), 
            ("service", "text"),
            ("product", "text")
        ])

        # Text index for checkinstances
        dbclient.create_index(pentest, "checkinstances", [
            ("target_repr", "text"),
            ("notes", "text"),
            ("status", "text")
        ])
        
        # Text index for terminalsessions
        dbclient.create_index(pentest, "terminalsessions", [
            ("name", "text"),
            ("logs", "text")
        ])
        
        # Compound indexes for performance
        dbclient.create_index(pentest, "ips", [("pentest_id", 1), ("ip", 1)])
        dbclient.create_index(pentest, "ports", [("ip", 1), ("port", 1)])
        dbclient.create_index(pentest, "checkinstances", [("target_iid", 1), ("target_type", 1)])
        dbclient.create_index(pentest, "terminalsessions", [("user", 1), ("status", 1)])
        
        logger.info(f"Created search indexes for pentest: {pentest}")
        
    except Exception as e:
        logger.warning(f"Failed to create some indexes for {pentest}: {e}")

def escape_regex(text: str) -> str:
    """
    Escape special regex characters in search text.
    
    Args:
        text (str): Text to escape
        
    Returns:
        str: Escaped text safe for regex
    """
    return re.escape(text)

def build_text_search_query(query: str, fields: List[str]) -> Dict[str, Any]:
    """
    Build MongoDB text search query for specified fields.
    
    Args:
        query (str): Search query
        fields (List[str]): List of fields to search in
        
    Returns:
        Dict[str, Any]: MongoDB query
    """
    if not query.strip():
        return {}
    
    # Use MongoDB text search if available, otherwise use regex
    escaped_query = escape_regex(query.strip())
    regex_conditions = []
    
    for field in fields:
        regex_conditions.append({
            field: {"$regex": escaped_query, "$options": "i"}
        })
    
    if len(regex_conditions) == 1:
        return regex_conditions[0]
    else:
        return {"$or": regex_conditions}

def search_hosts(pentest: str, query: str, limit: int, offset: int) -> List[Dict[str, Any]]:
    """
    Search in hosts (ips collection).
    
    Args:
        pentest (str): Pentest name
        query (str): Search query
        limit (int): Maximum results
        offset (int): Offset for pagination
        
    Returns:
        List[Dict[str, Any]]: Search results
    """
    dbclient = DBClient.getInstance()
    search_fields = ["ip", "hostname", "notes", "infos.os"]
    
    search_query = build_text_search_query(query, search_fields)
    if not search_query:
        return []
    
    results = []
    cursor = dbclient.findInDb(pentest, "ips", search_query, multi=True, skip=offset, limit=limit)
    
    for host_data in cursor:
        # Find matching snippets
        matches = []
        for field in search_fields:
            field_value = ""
            if field == "infos.os":
                field_value = str(host_data.get("infos", {}).get("os", ""))
            else:
                field_value = str(host_data.get(field.split(".")[0], ""))
            
            if field_value and re.search(escape_regex(query), field_value, re.IGNORECASE):
                snippet = field_value[:100] + "..." if len(field_value) > 100 else field_value
                matches.append(f"{field}: {snippet}")
        
        hostname = host_data.get("hostname", "")
        ip = host_data.get("ip", "")
        label = f"{hostname} ({ip})" if hostname else ip
        
        result = {
            "id": f"host_{host_data['_id']}",
            "category": "hosts",
            "label": label,
            "description": f"Host: {ip}",
            "matches": matches,
            "data": {
                "_id": str(host_data["_id"]),
                "ip": ip,
                "hostname": hostname,
                "os": host_data.get("infos", {}).get("os", "")
            }
        }
        results.append(result)
    
    return results

def search_ports(pentest: str, query: str, limit: int, offset: int) -> List[Dict[str, Any]]:
    """
    Search in ports (from hosts.infos.ports).
    
    Args:
        pentest (str): Pentest name
        query (str): Search query
        limit (int): Maximum results
        offset (int): Offset for pagination
        
    Returns:
        List[Dict[str, Any]]: Search results
    """
    dbclient = DBClient.getInstance()
    search_fields = ["port", "proto", "service", "product", "version", "notes"]
    
    search_query = build_text_search_query(query, search_fields)
    if not search_query:
        return []
    
    results = []
    cursor = dbclient.findInDb(pentest, "ports", search_query, multi=True, skip=offset, limit=limit)
    
    for port_data in cursor:
        # Find matching snippets
        matches = []
        for field in search_fields:
            field_value = str(port_data.get(field, ""))
            if field_value and re.search(escape_regex(query), field_value, re.IGNORECASE):
                snippet = field_value[:100] + "..." if len(field_value) > 100 else field_value
                matches.append(f"{field}: {snippet}")
        
        ip = port_data.get("ip", "")
        port = port_data.get("port", "")
        service = port_data.get("service", "")
        
        label = f"{ip}:{port}"
        if service:
            label += f" ({service})"
        
        result = {
            "id": f"port_{port_data['_id']}",
            "category": "ports",
            "label": label,
            "description": f"Port {port} on {ip}",
            "matches": matches,
            "data": {
                "_id": str(port_data["_id"]),
                "host_id": str(port_data.get("parent", "")),
                "ip": ip,
                "port": int(port) if port.isdigit() else port,
                "protocol": port_data.get("proto", ""),
                "service": service
            }
        }
        results.append(result)
    
    return results

def search_checkinstances(pentest: str, query: str, limit: int, offset: int) -> List[Dict[str, Any]]:
    """
    Search in check instances.
    
    Args:
        pentest (str): Pentest name
        query (str): Search query
        limit (int): Maximum results
        offset (int): Offset for pagination
        
    Returns:
        List[Dict[str, Any]]: Search results
    """
    dbclient = DBClient.getInstance()
    search_fields = ["notes", "status"]
    
    # Build base query for checkinstances
    base_query = {"type": "checkinstance"}
    search_query = build_text_search_query(query, search_fields)
    
    if search_query:
        final_query = {"$and": [base_query, search_query]}
    else:
        # If no direct field matches, search in related check items
        from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
        check_items = CheckItem.fetchObjects("pollenisator", {
            "$or": [
                {"title": {"$regex": escape_regex(query), "$options": "i"}},
                {"category": {"$regex": escape_regex(query), "$options": "i"}},
                {"description": {"$regex": escape_regex(query), "$options": "i"}}
            ]
        })
        
        if check_items:
            check_item_ids = [ObjectId(check.getId()) for check in check_items]
            final_query = {"$and": [base_query, {"check_iid": {"$in": check_item_ids}}]}
        else:
            return []
    
    results = []
    cursor = dbclient.findInDb(pentest, "checkinstances", final_query, multi=True, skip=offset, limit=limit)
    
    for check_data in cursor:
        # Get the check item for more details
        check_item = None
        representation = "Unknown Check"
        
        if check_data.get("check_iid"):
            try:
                from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
                check_item = CheckItem.fetchObject("pollenisator", {"_id": ObjectId(check_data["check_iid"])})
                if check_item:
                    representation = check_item.title
            except:
                pass
        
        # Find matching snippets
        matches = []
        if check_data.get("notes") and re.search(escape_regex(query), check_data["notes"], re.IGNORECASE):
            snippet = check_data["notes"][:100] + "..." if len(check_data["notes"]) > 100 else check_data["notes"]
            matches.append(f"notes: {snippet}")
        
        if check_data.get("status") and re.search(escape_regex(query), check_data["status"], re.IGNORECASE):
            matches.append(f"status: {check_data['status']}")
        
        if check_item and re.search(escape_regex(query), representation, re.IGNORECASE):
            matches.append(f"check: {representation}")
        
        result = {
            "id": f"checkinstance_{check_data['_id']}",
            "category": "checkinstances",
            "label": representation,
            "description": f"Check instance: {representation}",
            "matches": matches,
            "data": {
                "_id": str(check_data["_id"]),
                "representation": representation,
                "status": check_data.get("status", ""),
                "target": {
                    "target_iid": str(check_data.get("target_iid", "")),
                    "target_type": check_data.get("target_type", "")
                }
            }
        }
        results.append(result)
    
    return results

def search_terminalsessions(pentest: str, query: str, limit: int, offset: int) -> List[Dict[str, Any]]:
    """
    Search in terminal sessions.
    
    Args:
        pentest (str): Pentest name
        query (str): Search query
        limit (int): Maximum results
        offset (int): Offset for pagination
        
    Returns:
        List[Dict[str, Any]]: Search results
    """
    dbclient = DBClient.getInstance()
    search_fields = ["name", "logs"]
    
    # Build search query
    search_conditions = []
    escaped_query = escape_regex(query)
    
    # Search in session name
    search_conditions.append({"name": {"$regex": escaped_query, "$options": "i"}})
    
    # Search in logs array (each log entry as string)
    search_conditions.append({"logs": {"$regex": escaped_query, "$options": "i"}})
    
    search_query = {"$or": search_conditions}
    
    results = []
    cursor = dbclient.findInDb(pentest, "terminalsessions", search_query, multi=True, skip=offset, limit=limit)
    
    for session_data in cursor:
        # Find matching snippets
        matches = []
        
        name = session_data.get("name", "")
        if name and re.search(escaped_query, name, re.IGNORECASE):
            matches.append(f"name: {name}")
        
        # Search in logs
        logs = session_data.get("logs", [])
        log_matches = 0
        for log_entry in logs:
            if isinstance(log_entry, str) and re.search(escaped_query, log_entry, re.IGNORECASE):
                log_matches += 1
                if len(matches) < 3:  # Limit to 3 matches to avoid too much data
                    snippet = log_entry[:100] + "..." if len(log_entry) > 100 else log_entry
                    matches.append(f"{snippet}")
        
        if log_matches > 3:
            matches.append(f"... and {log_matches - 3} more command matches")
        
        # Get target information
        target_info = ""
        visible_target = session_data.get("visible_target", "")
        if visible_target:
            target_info = f" on {visible_target}"
        
        result = {
            "id": f"terminal_{session_data['_id']}",
            "category": "terminals",
            "label": f"Terminal: {name}",
            "description": f"Terminal session{target_info}",
            "matches": matches,
            "data": {
                "_id": str(session_data["_id"]),
                "name": name,
                "target": visible_target,
                "last_command": logs[-1] if logs else "",
                "status": session_data.get("status", ""),
                "user": session_data.get("user", ""),
                "visible_target": visible_target if visible_target else "",
            }
        }
        results.append(result)
    
    return results

@permission("pentester")
def search_all(pentest: str, body: Dict[str, Any]) -> Union[ErrorStatus, Dict[str, Any]]:
    """
    Universal search across multiple data types.
    
    Args:
        pentest (str): Pentest name
        body (Dict[str, Any]): Search parameters
        
    Returns:
        Union[ErrorStatus, Dict[str, Any]]: Search results or error
    """
    # Extract search parameters
    query = body.get("query", "").strip()
    categories = body.get("categories", ["hosts", "ports", "checkinstances", "terminals"])
    if len(categories) == 0:
        categories = ["hosts", "ports", "checkinstances", "terminals"]
    limit = min(body.get("limit", 50), 200)  # Cap at 200 for performance
    offset = max(body.get("offset", 0), 0)
    
    if not query:
        return {"results": [], "total": 0, "hasMore": False}
    
    # Ensure indexes exist
    create_text_indexes(pentest)
    
    # Perform searches across different categories
    all_results = []
    total_found = 0
    
    try:
        # Calculate per-category limits for pagination
        per_category_limit = max(1, limit // len(categories))
        per_category_offset = offset // len(categories)
        
        if "hosts" in categories:
            host_results = search_hosts(pentest, query, per_category_limit, per_category_offset)
            all_results.extend(host_results)
            total_found += len(host_results)
        
        if "ports" in categories:
            port_results = search_ports(pentest, query, per_category_limit, per_category_offset)
            all_results.extend(port_results)
            total_found += len(port_results)
        
        if "checkinstances" in categories:
            check_results = search_checkinstances(pentest, query, per_category_limit, per_category_offset)
            all_results.extend(check_results)
            total_found += len(check_results)
        
        if "terminals" in categories:
            terminal_results = search_terminalsessions(pentest, query, per_category_limit, per_category_offset)
            all_results.extend(terminal_results)
            total_found += len(terminal_results)
        
        # Sort results by relevance (number of matches first, then alphabetically)
        all_results.sort(key=lambda x: (-len(x.get("matches", [])), x.get("label", "")))
        
        # Apply final limit and offset
        final_results = all_results[offset:offset + limit]
        
        # Determine if there are more results
        has_more = len(all_results) > offset + limit
        
        return {
            "results": final_results,
            "total": total_found,
            "hasMore": has_more
        }
        
    except Exception as e:
        logger.error(f"Search error in pentest {pentest}: {e}")
        return f"Search failed: {str(e)}", 500

@permission("pentester") 
def search_notes(pentest: str, body: Dict[str, Any]) -> Union[ErrorStatus, Dict[str, Any]]:
    """
    Search specifically in notes fields across different collections.
    
    Args:
        pentest (str): Pentest name
        body (Dict[str, Any]): Search parameters
        
    Returns:
        Union[ErrorStatus, Dict[str, Any]]: Search results or error
    """
    query = body.get("query", "").strip()
    limit = min(body.get("limit", 50), 200)
    offset = max(body.get("offset", 0), 0)
    
    if not query:
        return {"results": [], "total": 0, "hasMore": False}
    
    dbclient = DBClient.getInstance()
    all_results = []
    escaped_query = escape_regex(query)
    
    try:
        # Search in host notes
        host_cursor = dbclient.findInDb(pentest, "ips", 
            {"notes": {"$regex": escaped_query, "$options": "i"}}, 
            multi=True, limit=limit)
        
        for host_data in host_cursor:
            notes = host_data.get("notes", "")
            snippet = notes[:200] + "..." if len(notes) > 200 else notes
            
            result = {
                "id": f"host_note_{host_data['_id']}",
                "category": "notes", 
                "source_type": "host",
                "source_id": str(host_data["_id"]),
                "label": f"Host Note: {host_data.get('ip', 'Unknown')}",
                "content": snippet,
                "matches": [f"note: {snippet}"]
            }
            all_results.append(result)
        
        # Search in port notes  
        port_cursor = dbclient.findInDb(pentest, "ports",
            {"notes": {"$regex": escaped_query, "$options": "i"}},
            multi=True, limit=limit)
            
        for port_data in port_cursor:
            notes = port_data.get("notes", "")
            snippet = notes[:200] + "..." if len(notes) > 200 else notes
            
            result = {
                "id": f"port_note_{port_data['_id']}",
                "category": "notes",
                "source_type": "port", 
                "source_id": str(port_data["_id"]),
                "label": f"Port Note: {port_data.get('ip', '')}:{port_data.get('port', '')}",
                "content": snippet,
                "matches": [f"note: {snippet}"]
            }
            all_results.append(result)
        
        # Search in checkinstance notes
        check_cursor = dbclient.findInDb(pentest, "checkinstances",
            {"type": "checkinstance", "notes": {"$regex": escaped_query, "$options": "i"}},
            multi=True, limit=limit)
            
        for check_data in check_cursor:
            notes = check_data.get("notes", "")
            snippet = notes[:200] + "..." if len(notes) > 200 else notes
            
            result = {
                "id": f"check_note_{check_data['_id']}",
                "category": "notes",
                "source_type": "checkinstance",
                "source_id": str(check_data["_id"]),
                "label": f"Check Note",
                "content": snippet,
                "matches": [f"note: {snippet}"]
            }
            all_results.append(result)
        
        # Apply pagination
        paginated_results = all_results[offset:offset + limit]
        has_more = len(all_results) > offset + limit
        
        return {
            "results": paginated_results,
            "total": len(all_results),
            "hasMore": has_more
        }
        
    except Exception as e:
        logger.error(f"Notes search error in pentest {pentest}: {e}")
        return f"Notes search failed: {str(e)}", 500
