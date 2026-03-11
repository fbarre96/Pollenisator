#!/usr/bin/env python3

"""
Module for Google Workspace OAuth authentication.
"""

import os
import datetime
import base64
import hashlib
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlencode, urlparse, urlunparse
from flask import redirect, request, url_for
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.token import getTokenFor, decode_token
from pollenisator.core.components.logger_config import logger
from flask import Response, make_response, jsonify
import secrets

ErrorStatus = Tuple[str, int]

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:5000/api/v1/auth/google/callback")
GOOGLE_WORKSPACE_DOMAIN = os.environ.get("GOOGLE_WORKSPACE_DOMAIN", "")  # Optional domain restriction

# OAuth 2.0 scopes for Google Workspace
SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]

isdebug = bool(os.environ.get("FLASK_DEBUG", False))


def get_authorization_response_url() -> str:
    """
    Construct the proper authorization response URL, handling reverse proxy scenarios.
    
    When behind a reverse proxy (nginx), Flask may receive internal URLs (http://127.0.0.1:5000)
    instead of external URLs (https://example.com). This function reconstructs the correct URL
    using the GOOGLE_REDIRECT_URI or by checking X-Forwarded-* headers.
    
    Returns:
        str: The properly constructed authorization response URL.
    """
    # Option 1: Use the configured redirect URI with current query parameters
    # This is the most reliable method when GOOGLE_REDIRECT_URI is properly configured
    redirect_uri_parts = urlparse(GOOGLE_REDIRECT_URI)
    
    # Get current query parameters from the request
    query_params = request.args.to_dict()
    query_string = urlencode(query_params)
    
    # Reconstruct the URL using the configured redirect URI
    authorization_response = urlunparse((
        redirect_uri_parts.scheme,  # Use scheme from GOOGLE_REDIRECT_URI (https)
        redirect_uri_parts.netloc,  # Use host from GOOGLE_REDIRECT_URI
        redirect_uri_parts.path,    # Use path from GOOGLE_REDIRECT_URI
        '',                          # params (unused)
        query_string,                # query string from current request
        ''                           # fragment (unused)
    ))
    
    logger.debug(f"Constructed authorization response URL: {authorization_response}")
    return authorization_response


def is_google_auth_configured() -> bool:
    """
    Check if Google OAuth is properly configured.
    
    Returns:
        bool: True if Google OAuth credentials are configured, False otherwise.
    """
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def get_google_auth_flow() -> Optional[Flow]:
    """
    Create and return a Google OAuth flow object.
    
    Returns:
        Optional[Flow]: The OAuth flow object or None if not configured.
    """
    if not is_google_auth_configured():
        logger.error("Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.")
        return None
    
    try:
        client_config = {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI]
            }
        }
        
        flow = Flow.from_client_config(
            client_config=client_config,
            scopes=SCOPES,
            redirect_uri=GOOGLE_REDIRECT_URI
        )
        return flow
    except Exception as e:
        logger.error(f"Failed to create Google OAuth flow: {e}")
        return None


def google_login() -> Union[Any, ErrorStatus]:
    """
    Initiate Google OAuth login flow.
    
    Returns:
        Union[Any, ErrorStatus]: Redirect to Google OAuth consent screen or error.
    """
    if not is_google_auth_configured():
        return "Google authentication is not configured on this server", 503
    
    flow = get_google_auth_flow()
    if flow is None:
        return "Failed to initialize Google authentication", 500
    
    # Generate and store state token to prevent CSRF
    state = secrets.token_urlsafe(32)

    # Generate PKCE code_verifier and derive the code_challenge (S256).
    # The verifier is stored with the state so the callback can restore it on
    # the new Flow instance – without this, newer versions of requests-oauthlib
    # that auto-add code_challenge to the authorization URL would cause Google
    # to return (invalid_grant) Missing code verifier.
    code_verifier = secrets.token_urlsafe(96)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode('ascii')

    # Store state token in database with expiration (5 minutes)
    dbclient = DBClient.getInstance()
    expires_at = datetime.datetime.now() + datetime.timedelta(minutes=5)
    state_data = {
        "state": state,
        "code_verifier": code_verifier,
        "created_at": datetime.datetime.now(),
        "expires_at": expires_at
    }
    result = None
    if dbclient.cacher.isAvailable():
        result = dbclient.cacher.setCacheFromFindResult(f"oauth_state.{state}", state_data)
    if result is None:
        dbclient.insertInDb("pollenisator", "oauth_states", state_data)

    authorization_url, _ = flow.authorization_url(
        access_type='online',
        state=state,
        prompt='select_account',  # Force account selection
        code_challenge=code_challenge,
        code_challenge_method='S256'
    )
    
    return redirect(authorization_url)


def google_callback(code: str, state: str) -> Union[Any, ErrorStatus]:
    """
    Handle the OAuth callback from Google.
    
    Returns:
        Union[Any, ErrorStatus]: JWT token and user info or error.
    """
    if not is_google_auth_configured():
        return "Google authentication is not configured on this server", 503
    
    # Verify state token to prevent CSRF
    state_from_request = request.args.get('state')
    if not state_from_request:
        logger.warning("OAuth callback missing state parameter")
        return "Invalid state parameter", 400
    
    # Verify state token exists in database and is not expired
    dbclient = DBClient.getInstance()
    state_record = None
    if dbclient.cacher.isAvailable():
        state_record = dbclient.cacher.getCacheFromFindResult(f"oauth_state.{state_from_request}")
    if state_record is None:
        state_record = dbclient.findInDb("pollenisator", "oauth_states", {"state": state_from_request}, False)
    
    if state_record is None:
        logger.warning("OAuth state not found in database - possible CSRF attack or expired state")
        return "Invalid or expired state parameter", 400
    
    # Check if state has expired
    expires_at = state_record.get("expires_at")
    if expires_at and isinstance(expires_at, datetime.datetime):
        if datetime.datetime.now() > expires_at:
            logger.warning("OAuth state has expired")
            dbclient.deleteFromDb("pollenisator", "oauth_states", {"state": state_from_request}, False)
            return "State token has expired, please try again", 400
    
    # State is valid, delete it (one-time use)
    dbclient.deleteFromDb("pollenisator", "oauth_states", {"state": state_from_request}, False)
    
    # Retrieve the PKCE verifier persisted during the login step
    code_verifier = state_record.get('code_verifier')

    flow = get_google_auth_flow()
    if flow is None:
        return "Failed to initialize Google authentication", 500

    # Restore the PKCE code_verifier on the new Flow instance so that
    # fetch_token() includes it in the token request.
    if code_verifier:
        flow.code_verifier = code_verifier

    try:
        # Exchange authorization code for tokens
        # Use the proper authorization response URL to handle reverse proxy scenarios
        authorization_response_url = get_authorization_response_url()
        flow.fetch_token(authorization_response=authorization_response_url)
        credentials = flow.credentials
        
        # Verify the ID token
        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID
        )
        
        # Extract user information
        email = id_info.get('email')
        email_verified = id_info.get('email_verified', False)
        google_user_id = id_info.get('sub')
        name = id_info.get('name', '')
        given_name = id_info.get('given_name', '')
        family_name = id_info.get('family_name', '')
        picture = id_info.get('picture', '')
        
        if not email or not email_verified:
            logger.warning(f"Google authentication failed: email not verified for {email}")
            return "Email not verified with Google", 401
        
        # Optional: Check if user is from allowed domain
        if GOOGLE_WORKSPACE_DOMAIN:
            domain = email.split('@')[-1] if '@' in email else ''
            if domain.lower() != GOOGLE_WORKSPACE_DOMAIN.lower():
                logger.warning(f"User {email} not from allowed domain {GOOGLE_WORKSPACE_DOMAIN}")
                return f"Access restricted to {GOOGLE_WORKSPACE_DOMAIN} domain", 403
        
        # Check if user exists in database
        dbclient = DBClient.getInstance()
        user_record = dbclient.findInDb("pollenisator", "users", {"email": email}, False, use_cache=False)
        
        if user_record is None:
            # Auto-create user if they don't exist
            logger.info(f"Auto-creating user account for {email} via Google OAuth")
            
            # Generate username from email prefix
            username = email
            
            # Check if username already exists and make it unique if needed
            existing_user = dbclient.findInDb("pollenisator", "users", {"username": username}, False)
            if existing_user is not None:
                # Append part of google_user_id to make it unique
                username = f"{username}_{google_user_id[:8]}"
                logger.info(f"Username conflict resolved, using: {username}")
            
            # Create new user with OAuth information
            # Note: No password hash needed for OAuth users
            user_data = {
                "username": username,
                "email": email,
                "name": given_name or "",
                "surname": family_name or "",
                "google_id": google_user_id,
                "picture": picture,
                "auth_provider": "google",
                "mustChangePassword": False,  # OAuth users don't need password
                "scope": ["user"],  # Default user scope
                "created_via": "google_oauth",
                "created_at": datetime.datetime.now()
            }
            
            # Insert the new user
            insert_result = dbclient.insertInDb("pollenisator", "users", user_data)
            logger.info(f"Successfully created user account for {email} (username: {username})")
            
            # Fetch the newly created user record
            user_record = dbclient.findInDb("pollenisator", "users", {"email": email}, False)
        
        # Update last login and OAuth info
        update_data = {
            "last_login_provider": "google",
            "last_login": datetime.datetime.now(),
            "google_id": google_user_id,
            "picture": picture
        }
        dbclient.updateInDb("pollenisator", "users", {"email": email}, {"$set": update_data}, False)
        
        # Generate JWT token for the user
        username = user_record["username"]
        logger.info(f"User {username} ({email}) successfully logged in via Google")
        token = getTokenFor(username)
        decoded_token = decode_token(token)
        
        
        # Set token in httpOnly cookie
        response = make_response(jsonify({
            "mustChangePassword": False,  # OAuth users don't need to change password
            "username": username,
            "email": email,
            "name": name,
            "picture": picture,
            "session_expiration": decoded_token.get("exp", 0),
            "scopes": decoded_token.get("scope", [])
        }))
        response.set_cookie(
            'session_token',
            token,
            httponly=True,
            secure=not isdebug,
            samesite='Strict'
        )
        
        return response
        
    except ValueError as e:
        logger.error(f"Token verification failed: {e}")
        return "Invalid token", 401
    except Exception as e:
        logger.error(f"Google authentication error: {e}")
        return f"Authentication error: {str(e)}", 500


def get_google_auth_status() -> Dict[str, Any]:
    """
    Get the current status of Google authentication configuration.
    
    Returns:
        Dict[str, Any]: Configuration status information.
    """
    return {
        "enabled": is_google_auth_configured(),
        "domain_restriction": bool(GOOGLE_WORKSPACE_DOMAIN),
        "allowed_domain": GOOGLE_WORKSPACE_DOMAIN if GOOGLE_WORKSPACE_DOMAIN else None
    }


def cleanup_expired_oauth_states() -> int:
    """
    Clean up expired OAuth state tokens from the database.
    This should be called periodically (e.g., via a cron job or background task).
    
    Returns:
        int: Number of expired states deleted.
    """
    dbclient = DBClient.getInstance()
    now = datetime.datetime.now()
    
    # Find all expired states
    expired_states = dbclient.findInDb("pollenisator", "oauth_states", {
        "expires_at": {"$lt": now}
    }, True)
    
    count = 0
    if expired_states:
        for state_record in expired_states:
            dbclient.deleteFromDb("pollenisator", "oauth_states", {"_id": state_record["_id"]}, False)
            count += 1
    
    if count > 0:
        logger.info(f"Cleaned up {count} expired OAuth state tokens")
    
    return count
