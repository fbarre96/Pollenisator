"""
Migration script to merge remarks into defects collection.
This script will:
1. Copy all documents from 'remarks' collection to 'defects' collection with is_remark=True
2. Map remark fields to defect fields appropriately
3. Optionally remove the 'remarks' collection after successful migration
"""

import sys
import uuid
from typing import Any, Dict, List
from datetime import datetime
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.logger_config import logger


def migrate_remark_to_defect(remark: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a remark document to a defect document format.
    
    Args:
        remark (Dict[str, Any]): The remark document from the database
        
    Returns:
        Dict[str, Any]: The converted defect document
    """
    # Map remark fields to defect fields
    defect = {
        "_id": remark.get("_id", ObjectId()),
        "defect_id": remark.get("id", str(uuid.uuid4())),
        "common_translation_id": str(uuid.uuid4()),
        "title": remark.get("title", ""),
        "description": remark.get("description", remark.get("title", "")),
        "type": [remark.get("type", "neutral")],  # type in remarks becomes a list in defects
        "is_remark": True,
        
        # Default values for defect-specific fields
        "synthesis": "",
        "impacts": "",
        "ease": "",
        "impact": "",
        "risk": "",
        "cvss_score": 0.0,
        "cvss_string": "",
        "redactor": "N/A",
        "language": remark.get("language", ""),
        "notes": "",
        "target_id": None,
        "target_type": "",
        "index": 0,
        "proofs": [],
        "fixes": [],
        "creation_time": remark.get("creation_time", datetime.now()),
        "redacted_state": "New",
        "editor": "",
        "infos": {},
        "perimeter": remark.get("perimeter", []),
        "script": "",
        "visibility": remark.get("visibility", "all")
    }
    
    return defect


def migrate_remarks_in_database(pentest: str, dry_run: bool = False) -> Dict[str, Any]:
    """
    Migrate all remarks in a specific pentest database to defects collection.
    
    Args:
        pentest (str): The pentest database name
        dry_run (bool): If True, only show what would be migrated without making changes
        
    Returns:
        Dict[str, Any]: Migration statistics
    """
    dbclient = DBClient.getInstance()
    
    # Check if remarks collection exists
    collections = dbclient.listCollections(pentest)
    if "remarks" not in collections:
        logger.info(f"No remarks collection found in {pentest}, skipping")
        return {"pentest": pentest, "migrated": 0, "errors": 0, "skipped": True}
    
    # Fetch all remarks
    remarks = dbclient.findInDb(pentest, "remarks", {}, multi=True)
    if remarks is None:
        remarks = []
    
    remarks_list = list(remarks)
    total_remarks = len(remarks_list)
    
    logger.info(f"Found {total_remarks} remarks in {pentest}")
    
    if dry_run:
        logger.info(f"DRY RUN: Would migrate {total_remarks} remarks to defects")
        for remark in remarks_list:
            defect = migrate_remark_to_defect(remark)
            logger.info(f"  Would migrate remark: {remark.get('title', 'Untitled')} -> defect with is_remark=True")
        return {"pentest": pentest, "migrated": 0, "errors": 0, "dry_run": True, "total": total_remarks}
    
    migrated_count = 0
    error_count = 0
    
    for remark in remarks_list:
        try:
            defect = migrate_remark_to_defect(remark)
            
            # Check if a defect with this _id already exists
            existing = dbclient.findInDb(pentest, "defects", {"_id": defect["_id"]}, multi=False)
            
            if existing is not None:
                logger.warning(f"Defect with _id {defect['_id']} already exists in {pentest}, skipping remark '{remark.get('title', 'Untitled')}'")
                error_count += 1
                continue
            
            # Insert the migrated remark as a defect
            result = dbclient.insertInDb(pentest, "defects", defect, notify=True)
            
            if result and result.inserted_id:
                logger.info(f"Migrated remark '{remark.get('title', 'Untitled')}' to defect with is_remark=True")
                migrated_count += 1
            else:
                logger.error(f"Failed to migrate remark '{remark.get('title', 'Untitled')}'")
                error_count += 1
                
        except Exception as e:
            logger.error(f"Error migrating remark '{remark.get('title', 'Untitled')}': {str(e)}")
            error_count += 1
    
    return {
        "pentest": pentest,
        "total": total_remarks,
        "migrated": migrated_count,
        "errors": error_count
    }


def migrate_all_remarks(dry_run: bool = False, remove_old_collection: bool = False) -> List[Dict[str, Any]]:
    """
    Migrate remarks to defects in all pentest databases.
    
    Args:
        dry_run (bool): If True, only show what would be migrated without making changes
        remove_old_collection (bool): If True, remove the remarks collection after successful migration
        
    Returns:
        List[Dict[str, Any]]: List of migration results for each pentest
    """
    dbclient = DBClient.getInstance()
    
    # Get all pentest databases (excluding pollenisator system database)
    pentest_uuids = dbclient.listPentestUuids()
    
    # Also migrate templates in pollenisator database
    all_databases = ["pollenisator"] + pentest_uuids
    
    results = []
    
    for pentest in all_databases:
        logger.info(f"Processing {pentest}...")
        result = migrate_remarks_in_database(pentest, dry_run=dry_run)
        results.append(result)
        
        # Optionally remove the remarks collection after successful migration
        if not dry_run and remove_old_collection and result["migrated"] > 0 and result["errors"] == 0:
            try:
                dbclient.db[pentest]["remarks"].drop()
                logger.info(f"Removed remarks collection from {pentest}")
            except Exception as e:
                logger.error(f"Failed to remove remarks collection from {pentest}: {str(e)}")
    
    return results


def print_migration_summary(results: List[Dict[str, Any]]) -> None:
    """
    Print a summary of the migration results.
    
    Args:
        results (List[Dict[str, Any]]): List of migration results
    """
    total_migrated = sum(r.get("migrated", 0) for r in results)
    total_errors = sum(r.get("errors", 0) for r in results)
    total_pentests = len([r for r in results if not r.get("skipped", False)])
    
    print("\n" + "="*60)
    print("MIGRATION SUMMARY")
    print("="*60)
    print(f"Pentests processed: {total_pentests}")
    print(f"Total remarks migrated: {total_migrated}")
    print(f"Total errors: {total_errors}")
    print("\nDetails by pentest:")
    for result in results:
        if result.get("skipped"):
            continue
        pentest = result.get("pentest", "Unknown")
        migrated = result.get("migrated", 0)
        errors = result.get("errors", 0)
        total = result.get("total", 0)
        status = "DRY RUN" if result.get("dry_run") else "COMPLETED"
        print(f"  {pentest}: {migrated}/{total} migrated, {errors} errors [{status}]")
    print("="*60 + "\n")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Migrate remarks from remarks collection to defects collection with is_remark=True"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run without making any changes"
    )
    parser.add_argument(
        "--remove-old-collection",
        action="store_true",
        help="Remove the remarks collection after successful migration (not recommended for production)"
    )
    parser.add_argument(
        "--pentest",
        type=str,
        help="Migrate remarks for a specific pentest only (by UUID or 'pollenisator' for templates)"
    )
    
    args = parser.parse_args()
    
    try:
        dbclient = DBClient.getInstance()
        dbclient.connect()
        
        if not dbclient.isUserConnected():
            logger.error("Failed to connect to database")
            sys.exit(1)
        
        if args.pentest:
            # Migrate specific pentest
            logger.info(f"Migrating remarks in {args.pentest}...")
            result = migrate_remarks_in_database(args.pentest, dry_run=args.dry_run)
            results = [result]
        else:
            # Migrate all pentests
            logger.info("Migrating remarks in all pentest databases...")
            results = migrate_all_remarks(
                dry_run=args.dry_run,
                remove_old_collection=args.remove_old_collection
            )
        
        print_migration_summary(results)
        
        if args.dry_run:
            print("\nThis was a DRY RUN. No changes were made to the database.")
            print("Run without --dry-run to actually perform the migration.\n")
        else:
            print("\nMigration completed successfully!")
            if not args.remove_old_collection:
                print("Note: Old 'remarks' collections were kept. Use --remove-old-collection to remove them.\n")
        
    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
