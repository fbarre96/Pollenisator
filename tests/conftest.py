# Mock token functions at module level before any imports
from unittest.mock import patch, Mock
fake_admin_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInNjb3BlIjpbImFkbWluIiwidXNlciJdLCJleHAiOjk5OTk5OTk5OTl9.admin"

# Mock token verification early to prevent import issues
def mock_decode_token_func(token, *args, **kwargs):
    """Mock token decoding function."""
    if token.endswith(".pentester"):
        return {
            'sub': 'pentester',
            'scope': ['user', 'pentester'],
            'exp': 9999999999
        }
    return {
        'sub': 'admin',
        'scope': ['admin', 'user'],
        'exp': 9999999999
    }

def mock_verify_token_func(token, *args, **kwargs):
    """Mock token verification function."""
    return True

# Apply patches at module level
patch('pollenisator.server.token.decode_token', side_effect=mock_decode_token_func).start()
patch('pollenisator.server.token.decode_cookie', side_effect=mock_decode_token_func).start()
patch('pollenisator.server.token.verifyToken', return_value=True).start()
patch('pollenisator.server.token.generateNewToken', return_value=fake_admin_token).start()
patch('pollenisator.server.token.checkTokenValidity', return_value=True).start()

# Test configuration and fixtures
import pytest
import os
import tempfile
import json
from typing import Generator, Dict, Any

import mongomock
import fakeredis
from flask import Flask
from werkzeug.test import Client

from pollenisator.app_factory import create_app
from pollenisator.core.components.mongo import DBClient

# Import throwable database fixtures
from tests.fixtures.database_fixtures import (
    throwable_db,
    throwable_db_with_data, 
    real_throwable_db,
    real_throwable_db_with_data,
    test_data_builder,
    ThrowableDBClient
)



@pytest.fixture(scope="session")
def app() -> Generator[Flask, None, None]:
    """Create and configure a test Flask app."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Mock MongoDB with mongomock
        with patch('pollenisator.core.components.mongo.MongoClient') as mock_mongo:
            mock_client = mongomock.MongoClient()
            mock_mongo.return_value = mock_client
            
            # Mock Redis with fakeredis
            with patch('redis.Redis') as mock_redis:
                mock_redis.return_value = fakeredis.FakeRedis()
                
                # Create test app
                test_app = create_app(debug=True, async_mode='threading')
                test_app.config.update({
                    'TESTING': True,
                    'WTF_CSRF_ENABLED': False,
                    'SECRET_KEY': 'test-secret-key',
                    'UPLOAD_FOLDER': temp_dir,
                })
                
                yield test_app


@pytest.fixture
def client(app: Flask) -> Generator[Client, None, None]:
    """Create a test client."""
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture
def mock_db():
    """Mock database client."""
    with patch('pollenisator.core.components.mongo.DBClient.getInstance') as mock_db:
        mock_instance = Mock()
        mock_db.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def sample_pentest_data() -> Dict[str, Any]:
    """Sample pentest data for testing."""
    return {
        "pentest_type": "Web",
        "start_date": "2023-01-01T00:00:00",
        "end_date": "2023-01-31T23:59:59",
        "scope": "example.com,192.168.1.0/24",
        "settings": {
            "Add domains whose IP are in scope": 1,
            "Add domains who have a parent domain in scope": 0,
            "Add all domains found": 0,
            "mission_name": "Test Mission",
            "client_name": "Test Client",
            "lang": "en"
        },
        "pentesters": "admin,pentester1"
    }


@pytest.fixture
def auth_headers() -> Dict[str, str]:
    """Get authentication headers for testing."""
    # Return mock authorization header with a fake JWT token
    # This bypasses the need for actual login during testing
    mock_token = fake_admin_token
    return {'Authorization': f'Bearer {mock_token}'}

@pytest.fixture
def auth_pentester_headers() -> Dict[str, str]:
    """Get authentication headers for testing."""
    # Return mock authorization header with a fake JWT token
    # This bypasses the need for actual login during testing
    mock_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInNjb3BlIjpbImFkbWluIiwidXNlciJdLCJleHAiOjk5OTk5OTk5OTl9.pentester"
    return {'Authorization': f'Bearer {mock_token}'}


@pytest.fixture
def sample_defect() -> Dict[str, Any]:
    """Sample defect data."""
    return {
        "title": "SQL Injection",
        "description": "SQL injection vulnerability found",
        "impact": "Major",
        "ease": "Difficult",
        "risk": "Major",
        "cvss_score": 8.5,
        "type": ["Web"],
        "synthesis": "Critical SQL injection vulnerability",
        "fixes": [{
            "title": "Input Validation",
            "description": "Implement proper input validation",
            "execution": "Moderate",
            "gain": "Strong"
        }]
    }


@pytest.fixture
def sample_tool() -> Dict[str, Any]:
    """Sample tool data."""
    return {
        "name": "nmap",
        "wave": "Main",
        "scope": "192.168.1.0/24",
        "ip": "192.168.1.1",
        "port": "80",
        "proto": "tcp",
        "lvl": "network"
    }


# Mock data generators
class DataFactory:
    @staticmethod
    def create_user(username: str = "testuser") -> Dict[str, Any]:
        return {
            "username": username,
            "pwd": "password123",
            "name": "Test",
            "surname": "User",
            "email": f"{username}@test.com"
        }
    
    @staticmethod
    def create_ip(ip: str = "192.168.1.1") -> Dict[str, Any]:
        return {
            "ip": ip,
            "notes": "Test IP",
            "in_scopes": ["Main"]
        }
    
    @staticmethod
    def create_port(ip: str = "192.168.1.1", port: str = "80") -> Dict[str, Any]:
        return {
            "ip": ip,
            "port": port,
            "proto": "tcp",
            "service": "http",
            "product": "Apache",
            "notes": "Web server"
        }


@pytest.fixture
def data_factory():
    """Data factory for creating test objects."""
    return DataFactory


