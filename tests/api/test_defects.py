"""
Tests for defect management endpoints
"""
import json
from unittest.mock import patch, Mock
from werkzeug.test import Client
from bson import ObjectId


class TestDefectManagement:
    """Test defect management operations."""
    
    def test_create_defect_success(self, client: Client, mock_db, auth_headers, sample_defect):
        """Test successful defect creation."""
        mock_result = Mock()
        mock_result.inserted_id = ObjectId("507f1f77bcf86cd799439011")
        mock_db.insertInDb.return_value = mock_result
        
        with patch('pollenisator.server.servermodels.defect.doInsert', 
                   return_value={"res": True, "iid": "507f1f77bcf86cd799439011"}):
            response = client.post('/api/v1/defects/test-pentest',
                                 headers=auth_headers,
                                 json=sample_defect)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["res"] is True
        assert "iid" in data
    
    def test_create_defect_validation_error(self, client: Client, auth_headers):
        """Test defect creation with validation errors."""
        invalid_defect = {
            "title": "",  # Empty title
            "description": "Test description",
            "risk": "Critical"
            # Missing required fields
        }
        
        response = client.post('/api/v1/defects/test-pentest',
                             headers=auth_headers,
                             json=invalid_defect)
        
        assert response.status_code == 400
    
    def test_update_defect_success(self, client: Client, mock_db, auth_headers):
        """Test successful defect update."""
        def mock_find_in_db(_database, collection, _query, multi, *args, **kwargs):
            if collection == "defects":
                if multi:
                    return [{
                        "_id": ObjectId("507f1f77bcf86cd799439011"),
                        "title": "Original Title",
                        "description": "Original Description",
                        "risk": "Critical",
                        "infos":{}
                    }]
                return {
                    "_id": ObjectId("507f1f77bcf86cd799439011"),
                    "title": "Original Title",
                    "description": "Original Description",
                    "risk": "Critical",
                    "infos":{}
                }
            else:
                print("MOCK DB findInDb UNKNOWN CALL", collection, _query, args, kwargs)
                return None
           
        mock_db.findInDb.side_effect = mock_find_in_db
        mock_db.updateInDb.return_value = {"n": 1, "nModified": 1}
        
        updated_defect = {
            "title": "Updated Title",
            "description": "Updated Description",
            "risk": "Major"
        }
        
        response = client.put('/api/v1/defects/update/test-pentest/507f1f77bcf86cd799439011',
                            headers=auth_headers,
                            json=updated_defect)
        
        assert response.status_code == 200
    
    def test_update_nonexistent_defect(self, client: Client, mock_db, auth_headers):
        """Test updating a non-existent defect."""
        mock_db.findInDb.return_value = None
        
        response = client.put('/api/v1/defects/update/test-pentest/507f1f77bcf86cd799439011',
                            headers=auth_headers,
                            json={"title": "Updated", "risk": "Major"})
        
        assert response.status_code == 404
    
    def test_get_target_representation(self, client: Client, mock_db, auth_headers):
        """Test getting target representation for defects."""
        def mock_find_in_db(_database, collection, _query, multi=False, *args, **kwargs):
            if collection == "defects":
                if multi:
                    return [{
                        "_id": ObjectId("507f1f77bcf86cd799439011"),
                        "title": "Original Title",
                        "description": "Original Description",
                        "risk": "Critical",
                        "target_type": "ip",
                        "target_id": ObjectId("aaaaaa77bcf86cd799439011"),
                        "infos":{}
                    }]
                return {
                    "_id": ObjectId("507f1f77bcf86cd799439011"),
                    "title": "Original Title",
                    "description": "Original Description",
                    "risk": "Critical",
                    "infos":{}
                }
            if collection == "ips":
                if multi:
                    return [{
                        "_id": ObjectId("aaaaaa77bcf86cd799439011"),
                        "ip": "192.168.1.1"
                    }]
                return {
                    "_id": ObjectId("aaaaaa77bcf86cd799439011"),
                    "ip": "192.168.1.1"
                }
            else:
                print("MOCK DB findInDb UNKNOWN CALL", collection, _query, args, kwargs)
                return None
           
        mock_db.findInDb.side_effect = mock_find_in_db
        
        response = client.post('/api/v1/defects/test-pentest/getTargetRepr',
                                headers=auth_headers,
                                json=["507f1f77bcf86cd799439011"])
        
        assert response.status_code == 200
        data = response.get_json()
        assert "507f1f77bcf86cd799439011" in data
        assert data["507f1f77bcf86cd799439011"] == "192.168.1.1"
    
    def test_review_defect(self, client: Client, mock_db, auth_headers):
        """Test reviewing a defect."""
        mock_defect = {
            "_id": ObjectId("507f1f77bcf86cd799439011"),
            "title": "Test Defect",
            "redacted_state": "New"
        }
        mock_db.findInDb.return_value = mock_defect
        
        response = client.get('/api/v1/defects/test-pentest/review/507f1f77bcf86cd799439011',
                            headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["title"] == "Test Defect"
    

class TestDefectTemplates:
    """Test defect template operations."""
    
    def test_create_defect_template(self, client: Client, mock_db, auth_headers):
        """Test creating a defect template."""
        template_data = {
            "title": "SQL Injection Template",
            "description": "Template for SQL injection vulnerabilities",
            "impact": "Major",
            "ease": "Moderate",
            "risk": "Major",
            "type": ["Application"],
            "language": "en",
            "perimeter": ["Web"],
            "fixes": [{
                "title": "Input Validation",
                "description": "Implement proper input validation",
                "execution": "Moderate",
                "gain": "Strong"
            }],
            "is_template": True,
            "is_remark": False,
            "is_suggestion": True
        }
        def mock_find_in_db(_database, collection, _query, multi=False, *args, **kwargs):
            if collection == "defects":
                return None
        def mock_insert_in_db(_database, collection, _document, *args, **kwargs):
            mock_result = Mock()
            mock_result.inserted_id = ObjectId("507f1f77bcf86cd799439011")
            return mock_result
        mock_db.insertInDb.side_effect = mock_insert_in_db
        mock_db.findInDb.side_effect = mock_find_in_db
        
        response = client.post('/api/v1/report/DefectTemplates/insert',
                             headers=auth_headers,
                             json=template_data)
        
        assert response.status_code == 200
    
class TestDefectValidation:
    """Test defect data validation."""
    
    def test_validate_cvss_score(self, client: Client, auth_headers):
        """Test CVSS score validation."""
        invalid_defect = {
            "title": "Test Defect",
            "description": "Test description",
            "risk": "Critical",
            "cvss_score": 15.0  # Invalid score > 10
        }
        
        response = client.post('/api/v1/defects/test-pentest',
                             headers=auth_headers,
                             json=invalid_defect)
        
        assert response.status_code == 400
    
    def test_validate_risk_enum(self, client: Client, auth_headers):
        """Test risk enumeration validation."""
        invalid_defect = {
            "title": "Test Defect",
            "description": "Test description",
            "risk": "Super Critical"  # Invalid enum value
        }
        
        response = client.post('/api/v1/defects/test-pentest',
                             headers=auth_headers,
                             json=invalid_defect)
        
        assert response.status_code == 400
    
    def test_validate_ease_enum(self, client: Client, auth_headers):
        """Test ease enumeration validation."""
        invalid_defect = {
            "title": "Test Defect",
            "description": "Test description",
            "ease": "Super Easy"  # Invalid enum value
        }
        
        response = client.post('/api/v1/defects/test-pentest',
                             headers=auth_headers,
                             json=invalid_defect)
        
        assert response.status_code == 400
    
    def test_validate_fixes_structure(self, client: Client, auth_headers):
        """Test fixes array structure validation."""
        defect_with_invalid_fixes = {
            "title": "Test Defect",
            "description": "Test description",
            "fixes": [{
                "title": "Fix Title",
                "execution": "Invalid Execution"  # Invalid enum value
            }]
        }
        
        response = client.post('/api/v1/defects/test-pentest',
                             headers=auth_headers,
                             json=defect_with_invalid_fixes)
        
        assert response.status_code == 400
