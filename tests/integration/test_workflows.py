"""
Integration tests for end-to-end workflows
"""
import json
import tempfile
from unittest.mock import patch, Mock
from werkzeug.test import Client


class TestPentestWorkflow:
    """Test complete pentest workflow."""
    
    def test_complete_pentest_lifecycle(self, client: Client, mock_db, sample_pentest_data, auth_headers):
        """Test complete pentest lifecycle from creation to deletion."""
        # Step 1: Create pentest
        mock_db.registerPentest.return_value = True, "3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"
        sample_pentest_data["pentest"] = "integration-test"  # Add 'f' field for pentest type
        with patch('pollenisator.server.mongo.preparePentest', return_value=("", True)):
            create_response = client.post('/api/v1/pentest/createPentest',
                                        headers=auth_headers,
                                        json=sample_pentest_data)
            assert create_response.status_code == 200
        
        # Step 2: Add users to pentest
        mock_db.addPentestUser.return_value = True
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        mock_db.getPentestOwner.return_value = "admin"
        mock_db.getPentestUsers.return_value = [{"username": "admin", "role": "owner"}]
        user_response = client.post('/api/v1/pentest/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/users',
                                  headers=auth_headers,
                                  json={'username': 'testuser'})
        assert user_response.status_code == 200
        
        # Step 3: Add scope items
        mock_db.insertInDb.return_value = Mock(inserted_id="scope_id")
        scope_data = {
            "wave": "Main",
            "scope": "192.168.1.0/24",
            "notes": "Internal network"
        }
        scope_response = client.post('/api/v1/insert/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/scopes',
                                   headers=auth_headers,
                                   json={"pipeline": json.dumps(scope_data)})
        assert scope_response.status_code == 200
        
        # Step 4: Add IP addresses
        ip_data = {
            "ip": "192.168.1.100",
            "notes": "Web server",
            "in_scopes": ["Main"]
        }
        ip_response = client.post('/api/v1/insert/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ips',
                                headers=auth_headers,
                                json={"pipeline": json.dumps(ip_data)})
        assert ip_response.status_code == 200
        
        # Step 5: Add ports
        port_data = {
            "ip": "192.168.1.100",
            "port": "80",
            "proto": "tcp",
            "service": "http"
        }
        port_response = client.post('/api/v1/insert/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/ports',
                                  headers=auth_headers,
                                  json={"pipeline": json.dumps(port_data)})
        assert port_response.status_code == 200
        
        # Step 6: Add defects
        defect_data = {
            "title": "SQL Injection",
            "description": "SQL injection found in login form",
            "impact": "Critical",
            "risk": "Critical",
            "target_type": "port",
            "target_id": "port_id"
        }
        with patch('pollenisator.server.servermodels.defect.doInsert',
                   return_value={"res": True, "iid": "defect_id"}):
            defect_response = client.post('/api/v1/defects/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90',
                                        headers=auth_headers,
                                        json=defect_data)
            assert defect_response.status_code == 200
        
        # Step 7: Generate report
        with patch('pollenisator.server.modules.report.report.generateReport',
                   return_value=Mock(status_code=200)):
            report_response = client.post('/api/v1/report/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90',
                                        headers=auth_headers,
                                        json={
                                            "templateName": "template.docx",
                                            "mainRedactor": "admin",
                                            "lang": "en"
                                        })
            # Note: This endpoint doesn't exist in your API, adjust as needed
        


class TestToolExecutionWorkflow:
    """Test tool execution workflows."""
    
    def test_tool_queue_and_execution_workflow(self, client: Client, mock_db, auth_headers):
        """Test queuing and executing tools."""
        # Step 1: Create a tool
        tool_data = {
            "name": "nmap",
            "command_iid": "command_id",
            "wave": "Main",
            "ip": "192.168.1.1",
            "port": "80",
            "proto": "tcp"
        }
        mock_db.listPentestUuids.return_value = ["3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90"]
        mock_db.insertInDb.return_value = Mock(inserted_id="tool_id")
        
        tool_response = client.post('/api/v1/insert/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/tools',
                                  headers=auth_headers,
                                  json={"pipeline": json.dumps(tool_data)})
        assert tool_response.status_code == 200
        
        # Step 2: Queue the tool
        with patch('pollenisator.core.models.tool.Tool.queueTasks',
                   return_value={"successes": [{"tool_iid": "tool_id"}], "failures": []}):
            queue_response = client.post('/api/v1/tools/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/queueTasks',
                                       headers=auth_headers,
                                       json=["tool_id"])
            assert queue_response.status_code == 200
        
        # Step 3: Check tool status
        mock_db.findInDb.return_value = {
            "_id": "tool_id",
            "name": "nmap",
            "status": ["queued"]
        }
        
        status_response = client.post('/api/v1/find/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/tools',
                                    headers=auth_headers,
                                    json={"pipeline": '{"_id": "tool_id"}'})
        assert status_response.status_code == 200
        
        # Step 4: Simulate tool completion and result import
        class mockResult:
            def __init__(self, raw_result):
                self.raw_result = raw_result    
        mock_db.updateInDb.return_value = mockResult({"n": 1, "nModified": 1, "ok": 1})
        
        completion_response = client.post('/api/v1/update/3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90/tools',
                                        headers=auth_headers,
                                        json={
                                            "pipeline": '{"_id": "tool_id"}',
                                            "updatePipeline": '{"$set": {"status": ["done"], "datef": "2023-01-01T12:00:00"}}'
                                        })
        assert completion_response.status_code == 200


class TestPermissionsWorkflow:
    """Test permission-based workflows."""
    
    def test_admin_workflow(self, client: Client, mock_db):
        """Test admin-only operations."""
        # Admin login
        def mock_find_in_db(pentest, collection , query, multi=True, *args, **kwargs):
            if collection == "users":
                if multi:
                    return [
                            {
                                "username": "admin",
                                "hash": "$2b$12$hashed_password",
                                "scope": ["admin", "user"],
                                "mustChangePassword": False
                            },
                            {
                                "username": "pentester",
                                "hash": "$2b$12$hashed_password",
                                "scope": ["user", "pentester"],
                                "mustChangePassword": False
                            }
                        ]
                if query.get("username") == "admin":
                    return {
                        "username": "admin",
                        "hash": "$2b$12$hashed_password",
                        "scope": ["admin"],
                        "mustChangePassword": False
                    }
                elif query.get("username") == "pentester":
                    return {
                        "username": "pentester",
                        "hash": "$2b$12$hashed_password",
                        "scope": ["user", "pentester"],
                        "mustChangePassword": False
                    }
                elif query.get("username") == "newuser":
                    return None
            print("Unexpected call "+str((pentest, collection , query, multi, args, kwargs)))
        
        mock_db.findInDb.side_effect = mock_find_in_db
        
        with patch('bcrypt.checkpw', return_value=True):
            login_response = client.post('/api/v1/login', json={
                'username': 'admin',
                'pwd': 'password'
            })
        assert login_response.status_code == 200
        token = login_response.get_json()['token']
        assert token != ""
        assert token.startswith("ey")  # Basic check for JWT format
       
        admin_headers = {'Authorization': f'Bearer {token}'}
        
        # Test admin operations
        # 1. Create user
        mock_db.insertInDb.return_value = Mock(inserted_id="new_user_id")
        create_user_response = client.post('/api/v1/user/register',
                                         headers=admin_headers,
                                         json={
                                             'username': 'newuser',
                                             'pwd': 'password123'
                                         })
        if create_user_response.status_code != 200:
            print(create_user_response.get_data(as_text=True))
        assert create_user_response.status_code == 200
        
        # 2. List users
        mock_db.aggregateFromDb.return_value = [
            {"username": "admin", "scope": ["admin", "user"]},
            {"username": "newuser", "scope": ["user"]}
        ]
        list_users_response = client.get('/api/v1/admin/listUsers',
                                       headers=admin_headers)
        assert list_users_response.status_code == 200
        def new_mock_find_in_db(pentest, collection , query, multi=True, *args, **kwargs):
            if query.get("username") == "newuser":
                return {
                    "username": "newuser",
                    "hash": "$2b$12$hashed_password",
                    "scope": ["user"],
                    "mustChangePassword": False
                }
        mock_db.findInDb.side_effect = new_mock_find_in_db
        # 3. Reset password
        mock_db.updateInDb.return_value = {"n": 1, "nModified": 1}
        reset_password_response = client.post('/api/v1/admin/resetPassword',
                                            headers=admin_headers,
                                            json={
                                                'username': 'newuser',
                                                'newPwd': 'newpassword123'
                                            })
        assert reset_password_response.status_code == 200
    
    def test_pentester_workflow(self, client: Client, mock_db):
        """Test pentester-level operations."""
        # Pentester login
        mock_db.findInDb.return_value = {
            "username": "pentester",
            "hash": "$2b$12$hashed_password",
            "scope": ["user", "pentester"],
            "mustChangePassword": False
        }
        
        with patch('bcrypt.checkpw', return_value=True):
            login_response = client.post('/api/v1/login', json={
                'username': 'pentester',
                'pwd': 'password'
            })
        
        assert login_response.status_code == 200
        token = login_response.get_json()['token']
        pentester_headers = {'Authorization': f'Bearer {token}'}
        
        
        
        # 1. Generate reports
        with patch('pollenisator.server.modules.report.report.generateReport',
                   return_value=Mock(status_code=200)):
            # This would be the actual report endpoint when implemented
            pass
