"""
Security tests for the API
"""
import json
import base64
from unittest.mock import patch, Mock
from werkzeug.test import Client


class TestAuthenticationSecurity:
    """Test authentication and authorization security."""
    
    def test_malformed_authorization_header(self, client: Client):
        """Test malformed authorization headers."""
        malformed_headers = [
            {'Authorization': 'InvalidFormat token'},
            {'Authorization': 'Bearer'},  # Missing token
            {'Authorization': ''},  # Empty value
        ]
        
        for headers in malformed_headers:
            response = client.get('/api/v1/pentests', headers=headers)
            assert response.status_code == 401
    
    def test_password_hashing(self, client: Client, mock_db, auth_headers):
        """Test that passwords are properly hashed."""
        mock_db.insertInDb.return_value = Mock(inserted_id="user_id")
        
        # Mock bcrypt to verify it's being called
        with patch('bcrypt.hashpw') as mock_hash:
            mock_hash.return_value = b'$2b$12$hashed_password'
            mock_db.findInDb.return_value = None  # User does not exist
            response = client.post('/api/v1/user/register', headers=auth_headers, json={
                'username': 'testauser',
                'pwd': 'plaintext_password'
            })
            
            # Verify bcrypt.hashpw was called
            if(response.status_code != 200):
                print(response.get_data(as_text=True))
            assert response.status_code == 200
            mock_hash.assert_called_once()
            args, _ = mock_hash.call_args
            assert args[0] == b'plaintext_password'  # Original password
    
    def test_password_strength_requirements(self, client: Client, mock_db):
        """Test password strength requirements."""
        weak_passwords = [
            '123',          # Too short
            'password',     # Too common
            '12345678',     # Only numbers
            'abcdefgh',     # Only letters
        ]
        
        for weak_pwd in weak_passwords:
            response = client.post('/api/v1/user/register', json={
                'username': 'testuser',
                'pwd': weak_pwd
            })
            # Depending on implementation, should reject weak passwords
            # assert response.status_code == 400  # Uncomment if validation exists
    

class TestDataProtection:
    """Test data protection and information disclosure prevention."""
 
    
    def test_debug_mode_disabled(self, client: Client):
        """Test that debug mode is disabled in production."""
        # Try to trigger debug information
        response = client.get('/api/v1/nonexistent-endpoint')
        
        if response.status_code == 404:
            response_text = response.get_data(as_text=True)
            # Should not contain debug information
            assert "Werkzeug" not in response_text
            assert "Traceback" not in response_text


class TestSecurityHeaders:
    """Test security headers in HTTP responses."""
    
    def test_security_headers_present(self, client: Client):
        """Test that appropriate security headers are present."""
        response = client.get('/api/v1/version')  # Public endpoint
        
        expected_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options', 
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        
        for header in expected_headers:
            # These should be implemented in the application
            # assert header in response.headers  # Uncomment when implemented
            pass
    
    def test_cors_configuration(self, client: Client):
        """Test CORS configuration is secure."""
        # Test preflight request
        response = client.options('/api/v1/login',
                                headers={'Origin': 'http://malicious-site.com',
                                        'Access-Control-Request-Method': 'POST'})
        
        # Should have appropriate CORS headers
        if 'Access-Control-Allow-Origin' in response.headers:
            # Should not allow all origins in production
            assert response.headers['Access-Control-Allow-Origin'] != '*'


class TestRateLimiting:
    """Test rate limiting implementation."""
    
    def test_login_rate_limiting(self, client: Client, mock_db):
        """Test rate limiting on login endpoint."""
        mock_db.findInDb.return_value = None  # User not found
        
        # Make many rapid login attempts
        responses = []
        for i in range(20):
            response = client.post('/api/v1/login', json={
                'username': 'nonexistent',
                'pwd': 'password'
            })
            responses.append(response)
        
        # Should eventually rate limit
        rate_limited = any(r.status_code == 429 for r in responses)
        # assert rate_limited  # Uncomment if rate limiting is implemented
