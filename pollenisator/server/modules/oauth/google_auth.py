#!/usr/bin/env python3

"""
Module for Google Workspace OAuth authentication.

Uses shared helpers from ``oauth_utils`` for PKCE, state management,
identity resolution and session cookies.
"""

import os
import secrets
from typing import Any, Dict, Optional, Tuple, Union

from flask import redirect, request
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow

from pollenisator.core.components.logger_config import logger
from pollenisator.server.modules.oauth.oauth_utils import (
    build_callback_url,
    build_login_response,
    confirm_link,
    generate_pkce_pair,
    pop_oauth_state,
    resolve_or_create_user,
    set_session_cookie,
    store_oauth_state,
)

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


def is_google_auth_configured() -> bool:
    """Check if Google OAuth is properly configured."""
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def _get_google_flow() -> Optional[Flow]:
    """Create and return a Google OAuth flow object."""
    if not is_google_auth_configured():
        logger.error("Google OAuth not configured – set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")
        return None
    try:
        client_config = {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI],
            }
        }
        return Flow.from_client_config(
            client_config=client_config,
            scopes=SCOPES,
            redirect_uri=GOOGLE_REDIRECT_URI,
        )
    except Exception as e:
        logger.error("Failed to create Google OAuth flow: %s", e)
        return None


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------

def google_login() -> Union[Any, ErrorStatus]:
    """Initiate Google OAuth login flow (``GET /auth/google/login``)."""
    if not is_google_auth_configured():
        return "Google authentication is not configured on this server", 503

    flow = _get_google_flow()
    if flow is None:
        return "Failed to initialize Google authentication", 500

    state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce_pair()
    store_oauth_state(state, code_verifier)

    authorization_url, _ = flow.authorization_url(
        access_type="online",
        state=state,
        prompt="select_account",
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    return redirect(authorization_url)


def google_callback(code: str = "", state: str = "") -> Union[Any, ErrorStatus]:
    """Handle the OAuth callback from Google (``GET /auth/google/callback``)."""
    if not is_google_auth_configured():
        return "Google authentication is not configured on this server", 503

    # --- validate state / PKCE -----------------------------------------------
    state_from_request = request.args.get("state", "")
    if not state_from_request:
        logger.warning("OAuth callback missing state parameter")
        return "Invalid state parameter", 400

    state_record = pop_oauth_state(state_from_request)
    if state_record is None:
        return "Invalid or expired state parameter", 400

    code_verifier = state_record.get("code_verifier")

    flow = _get_google_flow()
    if flow is None:
        return "Failed to initialize Google authentication", 500
    if code_verifier:
        flow.code_verifier = code_verifier

    try:
        # --- exchange code for tokens ----------------------------------------
        authorization_response_url = build_callback_url(GOOGLE_REDIRECT_URI)
        flow.fetch_token(authorization_response=authorization_response_url)
        credentials = flow.credentials

        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
        )

        email = id_info.get("email")
        email_verified = id_info.get("email_verified", False)
        google_user_id = id_info.get("sub")
        given_name = id_info.get("given_name", "")
        family_name = id_info.get("family_name", "")
        picture = id_info.get("picture", "")

        if not email or not email_verified:
            logger.warning("Google auth: email not verified for %s", email)
            return "Email not verified with Google", 401

        # --- domain restriction ----------------------------------------------
        if GOOGLE_WORKSPACE_DOMAIN:
            domain = email.split("@")[-1] if "@" in email else ""
            if domain.lower() != GOOGLE_WORKSPACE_DOMAIN.lower():
                logger.warning("User %s not from allowed domain %s", email, GOOGLE_WORKSPACE_DOMAIN)
                return f"Access restricted to {GOOGLE_WORKSPACE_DOMAIN} domain", 403

        # --- resolve user ----------------------------------------------------
        user_info = {
            "given_name": given_name,
            "family_name": family_name,
            "picture": picture,
        }
        user, link_payload = resolve_or_create_user(email, "google", google_user_id, user_info)

        if link_payload is not None:
            # Frontend must ask the user to confirm linking
            from flask import jsonify, make_response
            return make_response(jsonify(link_payload), 200)

        if user is None:
            return "Failed to create or retrieve user account", 500

        logger.info("User %s (%s) logged in via Google", user["username"], email)
        return build_login_response(user)

    except ValueError as e:
        logger.error("Token verification failed: %s", e)
        return "Invalid token", 401
    except Exception as e:
        logger.error("Google authentication error: %s", e)
        return f"Authentication error: {str(e)}", 500


def google_link_confirm(body: Dict[str, str], **kwargs: Any) -> Union[Any, ErrorStatus]:
    """Confirm linking a Google identity (``POST /auth/google/link/confirm``)."""
    return confirm_link(body, **kwargs)


def get_google_auth_status() -> Dict[str, Any]:
    """Get the current status of Google authentication configuration."""
    return {
        "enabled": is_google_auth_configured(),
        "domain_restriction": bool(GOOGLE_WORKSPACE_DOMAIN),
        "allowed_domain": GOOGLE_WORKSPACE_DOMAIN if GOOGLE_WORKSPACE_DOMAIN else None,
    }
