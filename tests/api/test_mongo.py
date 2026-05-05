"""
Tests for MongoDB operations (CRUD operations)
"""
import json
from unittest.mock import patch, Mock
from werkzeug.test import Client
from bson import ObjectId


class TestMongoOperations:
    """Test MongoDB CRUD operations."""
    
    def test_find_operation_success(self, client: Client, mock_db, auth_headers):
        """Test successful find operation."""
        mock_result = {"_id": "ObjectId|507f1f77bcf86cd799439011", "ip": "192.168.1.1", "notes": "Test IP"}
        mock_db.findInDb.return_value = mock_result
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        response = client.post('/api/v1/find/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ips',
                             headers=auth_headers,
                             json={"pipeline": '{"ip": "192.168.1.1"}'})
        if (response.status_code != 200):
            print(response.get_data(as_text=True))
        assert response.status_code == 200
        data = response.get_json()
        assert data["ip"] == "192.168.1.1"
    
    def test_find_operation_many(self, client: Client, mock_db, auth_headers):
        """Test find operation with many=true."""
        mock_results = [
            {"_id": "ObjectId|507f1f77bcf86cd799439011", "ip": "192.168.1.1"},
            {"_id": "ObjectId|507f1f77bcf86cd799439012", "ip": "192.168.1.2"}
        ]
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        mock_db.findInDb.return_value = mock_results
        
        response = client.post('/api/v1/find/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ips',
                             headers=auth_headers,
                             json={"pipeline": "{}", "many": True})
        
        assert response.status_code == 200
        data = response.get_json()
        assert len(data) == 2
        assert data[0]["ip"] == "192.168.1.1"
    
    def test_find_operation_not_found(self, client: Client, mock_db, auth_headers):
        """Test find operation with no results."""
        mock_db.findInDb.return_value = None
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        response = client.post('/api/v1/find/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ips',
                             headers=auth_headers,
                             json={"pipeline": '{"ip": "nonexistent"}'})
        
        assert response.status_code == 404
        assert "Not found" in response.get_json()
    
    def test_find_invalid_pipeline(self, client: Client, auth_headers):
        """Test find operation with invalid pipeline."""
        response = client.post('/api/v1/find/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ips',
                             headers=auth_headers,
                             json={"pipeline": "invalid json"})
        
        assert response.status_code == 400
        assert "Pipeline argument was not valid" in response.get_json()
    
    def test_insert_operation_success(self, client: Client, mock_db, auth_headers):
        """Test successful insert operation."""
        mock_result = Mock()
        mock_result.inserted_id = ObjectId("507f1f77bcf86cd799439011")
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        mock_db.insertInDb.return_value = mock_result
        
        response = client.post('/api/v1/insert/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ips',
                             headers=auth_headers,
                             json={"pipeline": '{"ip": "192.168.1.100", "notes": "New IP"}'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert "507f1f77bcf86cd799439011" in data
    
    def test_insert_invalid_collection(self, client: Client, mock_db, auth_headers):
        """Test insert with invalid collection."""
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        response = client.post('/api/v1/insert/pollenisator/pentests',
                             headers=auth_headers,
                             json={"pipeline": '{"test": "data"}'})
        if (response.status_code != 403):
            print(response.get_data(as_text=True))
        assert response.status_code == 403
        assert "not a valid pollenisator collection" in response.get_json()
    
    def test_update_operation_success(self, client: Client, mock_db, auth_headers):
        """Test successful update operation."""
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        class mockResult:
            def __init__(self, raw_result):
                self.raw_result = raw_result    
        mock_db.updateInDb.return_value = mockResult({"n": 1, "nModified": 1, "ok": 1})
        
        response = client.post('/api/v1/update/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ips',
                             headers=auth_headers,
                             json={
                                 "pipeline": '{"ip": "192.168.1.1"}',
                                 "updatePipeline": '{"$set": {"notes": "Updated notes"}}'
                             })
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["nModified"] == 1
    
    def test_update_operation_many(self, client: Client, mock_db, auth_headers):
        """Test update operation with many=true."""
        class mockResult:
            def __init__(self, raw_result):
                self.raw_result = raw_result    
        mock_db.updateInDb.return_value = mockResult({"n": 3, "nModified": 3, "ok": 1})
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        response = client.post('/api/v1/update/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ips',
                             headers=auth_headers,
                             json={
                                 "pipeline": '{}',
                                 "updatePipeline": '{"$set": {"updated": true}}',
                                 "many": True
                             })
        
        assert response.status_code == 200
        data = response.get_json()
        print(data)
        assert data["nModified"] == 3
    
    def test_delete_operation_success(self, client: Client, mock_db, auth_headers):
        """Test successful delete operation."""
        mock_db.deleteFromDb.return_value = 1
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        response = client.post('/api/v1/delete/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ips',
                             headers=auth_headers,
                             json={"pipeline": '{"ip": "192.168.1.1"}'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data == 1
    
    def test_delete_operation_many(self, client: Client, mock_db, auth_headers):
        """Test delete operation with many=true."""
        mock_db.deleteFromDb.return_value = 5
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        response = client.post('/api/v1/delete/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ips',
                             headers=auth_headers,
                             json={"pipeline": '{}', "many": True})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data == 5
    
    def test_count_operation(self, client: Client, mock_db, auth_headers):
        """Test count operation."""
        mock_db.countInDb.return_value = 42
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        response = client.post('/api/v1/count/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ips',
                             headers=auth_headers,
                             json={"pipeline": "{}"})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data == 42
    
    def test_aggregate_operation(self, client: Client, mock_db, auth_headers):
        """Test aggregate operation."""
        mock_results = [
            {"_id": "tcp", "count": 50},
            {"_id": "udp", "count": 20}
        ]
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        mock_db.aggregateFromDb.return_value = mock_results
        
        response = client.post('/api/v1/aggregate/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ports',
                             headers=auth_headers,
                             json=[
                                 {"$group": {"_id": "$proto", "count": {"$sum": 1}}}
                             ])
        
        assert response.status_code == 200
        data = response.get_json()
        assert len(data) == 2
        assert data[0]["_id"] == "tcp"
    
    def test_bulk_delete_success(self, client: Client, mock_db, auth_headers):
        """Test bulk delete operation."""
        mock_db.deleteFromDb.return_value = 5  # Total deleted items
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        response = client.post('/api/v1/delete/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/bulk',
                             headers=auth_headers,
                             json={
                                 "ips": ["aaaaaa77bcf86cd799439011", "aaaaaa77bcf86cd799439012"],
                                 "ports": ["baaaaa77bcf86cd799439011", "baaaaa77bcf86cd799439012"],
                                 "tools": ["caaaaa77bcf86cd799439011"]
                             })
        
        print(response.get_data(as_text=True))
        assert response.status_code == 200
        # Should return total count across all collections
        data = response.get_json()
        assert isinstance(data, int)


