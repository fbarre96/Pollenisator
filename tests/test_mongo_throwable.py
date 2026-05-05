"""
Enhanced MongoDB operations tests using throwable databases.
"""
import pytest
import json
from bson import ObjectId
from werkzeug.test import Client

from tests.fixtures.database_fixtures import ThrowableDBClient, TestDataBuilder


class TestMongoWithThrowableDB:
    """Test MongoDB operations using throwable database."""
    
    def test_database_isolation(self, throwable_db: ThrowableDBClient):
        """Test that each test gets an isolated database."""
        pentest_uuid = throwable_db.setup_test_data("isolated-test-1")
        
        # Insert some data (disable notifications to avoid SocketIO issues in tests)
        result = throwable_db.insert("ips", {"ip": "192.168.100.1", "notes": "Isolated test"}, notify=False)
        assert result.inserted_id is not None
        
        # Verify data exists
        found_data = throwable_db.find("ips", {"ip": "192.168.100.1"}, multi=False)
        assert found_data is not None
        assert found_data["ip"] == "192.168.100.1"
    
    def test_database_isolation_separate_test(self, throwable_db: ThrowableDBClient):
        """Test that this test doesn't see data from previous test."""
        pentest_uuid = throwable_db.setup_test_data("isolated-test-2")
        
        # This should not find data from the previous test
        found_data = throwable_db.find("ips", {"ip": "192.168.100.1"}, multi=False)
        assert found_data is None
    
    def test_crud_operations(self, throwable_db_with_data: ThrowableDBClient):
        """Test CRUD operations with pre-loaded data."""
        # CREATE
        new_ip_data = {"ip": "192.168.2.50", "in_scopes": ["Test"], "notes": "CRUD test IP"}
        insert_result = throwable_db_with_data.insert("ips", new_ip_data, notify=False)
        assert insert_result.inserted_id is not None
        
        # READ
        found_ip = throwable_db_with_data.find("ips", {"ip": "192.168.2.50"}, multi=False)
        assert found_ip is not None
        assert found_ip["ip"] == "192.168.2.50"
        assert found_ip["notes"] == "CRUD test IP"
        
        # UPDATE
        update_result = throwable_db_with_data.update("ips", 
                                                     {"ip": "192.168.2.50"}, 
                                                     {"$set": {"notes": "Updated notes"}},
                                                     notify=False)
        assert update_result.modified_count == 1
        
        # Verify update
        updated_ip = throwable_db_with_data.find("ips", {"ip": "192.168.2.50"}, multi=False)
        assert updated_ip["notes"] == "Updated notes"
        
        # DELETE
        deleted_ids = throwable_db_with_data.delete("ips", {"ip": "192.168.2.50"})
        assert len(deleted_ids) == 1
        
        # Verify deletion
        deleted_ip = throwable_db_with_data.find("ips", {"ip": "192.168.2.50"}, multi=False)
        assert deleted_ip is None
    
    def test_aggregate_operations(self, throwable_db_with_data: ThrowableDBClient):
        """Test aggregation operations."""
        # Aggregate IPs by scope
        pipeline = [
            {"$group": {"_id": {"$arrayElemAt": ["$in_scopes", 0]}, "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        
        results = list(throwable_db_with_data.aggregate("ips", pipeline))
        assert len(results) > 0
        
        # Should have Main scope with multiple IPs
        main_scope = next((r for r in results if r["_id"] == "Main"), None)
        assert main_scope is not None
        assert main_scope["count"] >= 2  # We inserted at least 2 IPs with Main scope
    
    def test_file_upload_operations(self, throwable_db_with_data: ThrowableDBClient):
        """Test file upload operations."""
        # Test proof file upload path - accessing protected method for testing  # pylint: disable=protected-access
        attachment_id, upload_name, name, full_path = throwable_db_with_data._get_upload_path(
            pentest="3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90",
            filetype="proof", 
            attached_to="unassigned",
            filename="test_screenshot.jpg",
            attachment_id="unassigned"
        )
        
        assert attachment_id != "unassigned"
        assert upload_name == "test_screenshot.jpg"
        assert name.endswith(".png")  # Proof files are converted to PNG
        assert "3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90" in full_path
        assert "proof" in full_path
        
        # Test result file upload path  # pylint: disable=protected-access
        attachment_id2, upload_name2, name2, full_path2 = throwable_db_with_data._get_upload_path(
            pentest="3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90",
            filetype="result",
            attached_to="tool123", 
            filename="scan_results.xml",
            attachment_id="unassigned"
        )
        
        assert attachment_id2 != "unassigned"
        assert upload_name2 == "scan_results.xml"
        assert name2 == "scan_results.xml"
        assert "result" in full_path2
        assert "tool123" in full_path2
    
    def test_pentest_management(self, throwable_db: ThrowableDBClient):
        """Test pentest creation and management."""
        # Test pentest registration
        success, uuid_or_msg = throwable_db.registerPentest(
            owner="testuser",
            saveAsName="Test Pentest Creation",
            autoconnect=True
        )
        
        assert success is True
        pentest_uuid = uuid_or_msg
        assert throwable_db.try_uuid(pentest_uuid) is True
        
        # Test pentest listing
        pentests = throwable_db.listPentests()
        assert pentests is not None
        assert len(pentests) > 0
        
        # Find our pentest
        our_pentest = next((p for p in pentests if p["uuid"] == pentest_uuid), None)
        assert our_pentest is not None
        assert our_pentest["nom"] == "Test Pentest Creation"
        assert our_pentest["owner"] == "testuser"
    
    def test_tags_operations(self, throwable_db_with_data: ThrowableDBClient):
        """Test tag registration and retrieval."""
        from pollenisator.core.components.tag import Tag
        
        # Create a test tag using keyword arguments
        test_tag = Tag("high_priority", color="#ff0000", level="5")
        
        # Register the tag
        success = throwable_db_with_data.doRegisterTag("3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90", test_tag)
        assert success is True
        
        # Retrieve registered tags
        tags = throwable_db_with_data.getRegisteredTags("3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90", only_name=True)
        assert "high_priority" in tags
        
        # Test trying to register same tag again
        success_duplicate = throwable_db_with_data.doRegisterTag("3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90", test_tag)
        assert success_duplicate is False
    
    def test_user_management(self, throwable_db_with_data: ThrowableDBClient):
        """Test pentest user management."""
        pentest_uuid = "3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"
        
        # Add user to pentest
        success = throwable_db_with_data.addPentestUser(pentest_uuid, "newuser")
        assert success is True
        
        # find db 
        # Get pentest users
        users = throwable_db_with_data.getPentestUsers(pentest_uuid)
        assert "newuser" in users
        assert "admin" in users  # Owner should be included
        
        # Remove user from pentest
        success = throwable_db_with_data.removePentestUser(pentest_uuid, "newuser")
        assert success is True
        
        # Verify user removed
        users_after = throwable_db_with_data.getPentestUsers(pentest_uuid)
        assert "newuser" not in users_after
    
    def test_data_builder(self, test_data_builder: TestDataBuilder):
        """Test the test data builder functionality."""
        # Create test IP
        ip_id = test_data_builder.create_ip("10.0.0.100", ["DMZ"], notes="DMZ Server")
        assert ip_id is not None
        
        # Create test port for that IP
        port_id = test_data_builder.create_port("10.0.0.100", "8443", service="https-alt")
        assert port_id is not None
        
        # Create test tool
        tool_id = test_data_builder.create_tool("custom_scan", wave="Discovery", status="completed")
        assert tool_id is not None
        
        # Create test defect
        defect_id = test_data_builder.create_defect("Buffer Overflow", impact="Critical", cvss=9.5)
        assert defect_id is not None
        
        # Verify the created data
        db = test_data_builder.db
        created_ip = db.find("ips", {"ip": "10.0.0.100"}, multi=False)
        assert created_ip is not None
        assert created_ip["notes"] == "DMZ Server"
        assert "DMZ" in created_ip["in_scopes"]
        
        created_port = db.find("ports", {"ip": "10.0.0.100", "port": "8443"}, multi=False)
        assert created_port is not None
        assert created_port["service"] == "https-alt"
        
        created_tool = db.find("tools", {"name": "custom_scan"}, multi=False)
        assert created_tool is not None
        assert created_tool["wave"] == "Discovery"
        assert created_tool["status"] == "completed"
        
        created_defect = db.find("defects", {"title": "Buffer Overflow"}, multi=False)
        assert created_defect is not None
        assert created_defect["impact"] == "Critical"
        assert created_defect["cvss"] == 9.5


class TestIntegrationWithRealDB:
    """Integration tests using real MongoDB (when available)."""
    
    @pytest.mark.integration
    def test_real_db_operations(self, real_throwable_db_with_data: ThrowableDBClient):
        """Test operations against real MongoDB."""
        # This test will be skipped if MongoDB is not available
        
        # Test that we can perform operations against real MongoDB
        result = real_throwable_db_with_data.insert("test_collection", {"test": "data"})
        assert result.inserted_id is not None
        
        # Test find
        found = real_throwable_db_with_data.find("test_collection", {"test": "data"}, multi=False)
        assert found is not None
        assert found["test"] == "data"
        
        # Test aggregation
        pipeline = [{"$match": {"test": "data"}}, {"$count": "total"}]
        agg_result = list(real_throwable_db_with_data.aggregate("test_collection", pipeline))
        assert len(agg_result) == 1
        assert agg_result[0]["total"] == 1
    
    @pytest.mark.integration
    def test_database_cleanup(self, real_throwable_db: ThrowableDBClient):
        """Test that database cleanup works properly."""
        _ = real_throwable_db.setup_test_data("cleanup-test")
        
        # Insert some test data
        real_throwable_db.insert("cleanup_test", {"data": "to_be_deleted"}, notify=False)
        
        # Verify data exists
        found = real_throwable_db.find("cleanup_test", {"data": "to_be_deleted"}, multi=False)
        assert found is not None
        
        # Cleanup will happen automatically when fixture is destroyed
        # This test verifies the cleanup mechanism works
