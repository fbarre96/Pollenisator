#!/usr/bin/env python3

"""
Module for Google Workspace OAuth authentication.
"""

import os
from typing import Any, Dict, Optional, Tuple, Union
from flask import redirect, request, session, url_for
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.token import getTokenFor
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
    session['oauth_state'] = state
    
    authorization_url, _ = flow.authorization_url(
        access_type='online',
        state=state,
        prompt='select_account'  # Force account selection
    )
    
    return redirect(authorization_url)


def google_callback() -> Union[Any, ErrorStatus]:
    """
    Handle the OAuth callback from Google.
    
    Returns:
        Union[Any, ErrorStatus]: JWT token and user info or error.
    """
    if not is_google_auth_configured():
        return "Google authentication is not configured on this server", 503
    
    # Verify state token to prevent CSRF
    state = session.get('oauth_state')
    if not state or state != request.args.get('state'):
        logger.warning("OAuth state mismatch - possible CSRF attack")
        return "Invalid state parameter", 400
    
    # Clear the state from session
    session.pop('oauth_state', None)
    
    # Check for errors from Google
    error = request.args.get('error')
    if error:
        logger.warning(f"Google OAuth error: {error}")
        return f"Authentication failed: {error}", 401
    
    flow = get_google_auth_flow()
    if flow is None:
        return "Failed to initialize Google authentication", 500
    
    try:
        # Exchange authorization code for tokens
        flow.fetch_token(authorization_response=request.url)
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
                "created_at": dbclient.getTimestamp()
            }
            
            # Insert the new user
            insert_result = dbclient.insertInDb("pollenisator", "users", user_data)
            logger.info(f"Successfully created user account for {email} (username: {username})")
            
            # Fetch the newly created user record
            user_record = dbclient.findInDb("pollenisator", "users", {"email": email}, False)
        
        # Update last login and OAuth info
        update_data = {
            "last_login_provider": "google",
            "last_login": dbclient.getTimestamp(),
            "google_id": google_user_id,
            "picture": picture
        }
        dbclient.updateInDb("pollenisator", "users", {"email": email}, {"$set": update_data}, False)
        
        # Generate JWT token for the user
        username = user_record["username"]
        logger.info(f"User {username} ({email}) successfully logged in via Google")
        token = getTokenFor(username)
        
        # Set token in httpOnly cookie
        response = make_response(jsonify({
            "token": token,
            "mustChangePassword": False,  # OAuth users don't need to change password
            "username": username,
            "email": email,
            "name": name,
            "picture": picture
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
