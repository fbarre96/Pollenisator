"""
Tests for authentication endpoints
"""
import pytest
from unittest.mock import patch, Mock
from werkzeug.test import Client


class TestAuthentication:
    """Test authentication-related endpoints."""
    
    def test_login_success(self, client: Client, mock_db):
        """Test successful login."""
        # Mock user in database
        mock_db.findInDb.return_value = {
            "_id": "user_id",
            "username": "admin",
            "hash": "$2b$12$hashed_password",
            "scope": ["admin", "user"],
            "mustChangePassword": False
        }
        
        with patch('bcrypt.checkpw', return_value=True):
            response = client.post('/api/v1/login', json={
                'username': 'admin',
                'pwd': 'password'
            })
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'token' in data
        assert data['mustChangePassword'] is False
    
    def test_login_invalid_credentials(self, client: Client, mock_db):
        """Test login with invalid credentials."""
        mock_db.findInDb.return_value = None
        
        response = client.post('/api/v1/login', json={
            'username': 'invalid',
            'pwd': 'wrong'
        })
        
        assert response.status_code == 401
        assert 'Authentication failure' in response.get_json()
    
    def test_login_missing_parameters(self, client: Client):
        """Test login with missing parameters."""
        response = client.post('/api/v1/login', json={
            'username': 'admin'
            # Missing pwd
        })
        
        assert response.status_code == 400
    
    def test_connect_to_pentest_success(self, client: Client, mock_db, auth_headers):
        """Test successful connection to pentest."""
        # Mock different return values for different findInDb calls
        def mock_find_in_db(_database, collection, _query, *_args, **_kwargs):
            if collection == "pentests":
                return {
                    "nom": "Test Pentest",
                    "uuid": "test-pentest",
                }
            elif collection == "users":
                return {
                    "_id": "user_id",
                    "username": "admin",
                    "hash": "$2b$12$hashed_password",
                    "scope": ["admin", "user"],
                    "mustChangePassword": False
                }
            return None
            
        mock_db.findInDb.side_effect = mock_find_in_db
        mock_db.getPentestUsers.return_value = ["admin", "user1"]
        mock_db.getPentestOwner.return_value = "admin"
        mock_db.listPentestUuids.return_value = ["test-pentest"]  # Include our test pentest
        mock_db.countInDb.return_value = 1  # Avoid cheatsheet import
        
        response = client.post('/api/v1/login/test-pentest',
                             headers=auth_headers,
                             json={'addDefaultCommands': False})
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'token' in data
    
    def test_connect_to_nonexistent_pentest(self, client: Client, mock_db, auth_headers):
        """Test connection to non-existent pentest."""
        # Mock different return values for different findInDb calls
        def mock_find_in_db(_database, collection, _query, *_args, **_kwargs):
            if collection == "pentests":
                return None  # Pentest not found
            elif collection == "users":
                return {
                    "_id": "user_id", 
                    "username": "admin",
                    "hash": "$2b$12$hashed_password",
                    "scope": ["admin", "user"],
                    "mustChangePassword": False
                }
            return None
            
        mock_db.findInDb.side_effect = mock_find_in_db
        mock_db.listPentestUuids.return_value = ["test-pentest"]  # Include our test pentest
        mock_db.countInDb.return_value = 1  # Avoid cheatsheet import
        
        response = client.post('/api/v1/login/nonexistent', 
                             headers=auth_headers,
                             json={})
        
        assert response.status_code == 404
        assert 'Pentest not found' in response.get_json()
    
    def test_change_password_success(self, client: Client, mock_db, auth_headers):
        """Test successful password change."""
        mock_db.findInDb.return_value = {
            "username": "admin",
            "hash": "$2b$12$old_hashed_password"
            
        }
        mock_db.updateInDb.return_value = {"n": 1, "nModified": 1}
        
        with patch('bcrypt.checkpw', return_value=True):
            response = client.post('/api/v1/user/changePassword',
                                 headers=auth_headers,
                                 json={
                                     'oldPwd': 'oldpassword',
                                     'newPwd': 'Newpassword123!'
                                 })
        if response.status_code != 200:
            print(response.get_data(as_text=True))
        assert response.status_code == 200
    
    def test_change_password_wrong_old_password(self, client: Client, mock_db, auth_headers):
        """Test password change with wrong old password."""
        mock_db.findInDb.return_value = {
            "username": "admin",
            "hash": "$2b$12$old_hashed_password"
        }
        
        with patch('bcrypt.checkpw', return_value=False):
            response = client.post('/api/v1/user/changePassword',
                                 headers=auth_headers,
                                 json={
                                     'oldPwd': 'wrongold',
                                     'newPwd': 'Newpassword123!'
                                 })
        
        assert response.status_code == 403
        assert 'incorrect' in response.get_json()
    
    def test_request_empty_token(self, client: Client):
        """Test accessing protected endpoint without token."""
        response = client.get('/api/v1/pentests', headers={'Authorization': '', "Cookies": "session_token=;"})
        assert response.status_code == 401
        response = client.get('/api/v1/pentests', headers={'Authorization': ''})
        assert response.status_code == 401
        response = client.get('/api/v1/pentests', headers={"Cookies": "session_token=;"})
        assert response.status_code == 401


class TestUserManagement:
    """Test user management endpoints."""
    
    def test_create_user_success(self, client: Client, mock_db, auth_headers):
        """Test successful user creation."""
        mock_db.findInDb.return_value = None  # User doesn't exist
        mock_db.insertInDb.return_value = Mock(inserted_id="new_user_id")
        
        response = client.post('/api/v1/user/register',
                             headers=auth_headers,
                             json={
                                 'username': 'newuser',
                                 'pwd': 'password123',
                                 'name': 'New',
                                 'surname': 'User',
                                 'email': 'newuser@test.com'
                             })
        
        assert response.status_code == 200
    
    def test_create_existing_user(self, client: Client, mock_db, auth_headers):
        """Test creating a user that already exists."""
        mock_db.findInDb.return_value = {"username": "existing"}
        
        response = client.post('/api/v1/user/register',
                             headers=auth_headers,
                             json={
                                 'username': 'existing',
                                 'pwd': 'password123'
                             })
        
        assert response.status_code == 403
        assert 'already exists' in response.get_json()
    
    def test_update_user_info(self, client: Client, mock_db, auth_headers):
        """Test updating user information."""
        mock_db.findInDb.return_value = {"username": "testuser"}
        mock_db.updateInDb.return_value = {"n": 1, "nModified": 1}
        
        response = client.post('/api/v1/user/updateUserInfos',
                             headers=auth_headers,
                             json={
                                 'username': 'testuser',
                                 'name': 'Updated',
                                 'email': 'updated@test.com'
                             })
        
        assert response.status_code == 200
    
    def test_delete_user(self, client: Client, mock_db, auth_headers):
        """Test user deletion."""
        mock_db.findInDb.return_value = {"username": "todelete"}
        mock_db.deleteInDb.return_value = 1
        
        response = client.delete('/api/v1/user/delete/todelete',
                               headers=auth_headers)
        
        assert response.status_code == 200
        assert 'successfully deleted' in response.get_json()
    
    def test_list_users(self, client: Client, mock_db, auth_headers):
        """Test listing all users."""
        mock_db.aggregateFromDb.return_value = [
            {"username": "admin", "scope": ["admin", "user"]},
            {"username": "user1", "scope": ["user"]}
        ]
        
        response = client.get('/api/v1/admin/listUsers', headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert len(data) == 2
        assert data[0]['username'] == 'admin'
    
    def test_search_users(self, client: Client, mock_db, auth_headers):
        """Test searching users."""
        mock_db.findInDb.return_value = [
            {"username": "admin"},
            {"username": "administrator"}
        ]
        
        response = client.get('/api/v1/user/searchUsers/adm', headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'admin' in data
        assert 'administrator' in data
