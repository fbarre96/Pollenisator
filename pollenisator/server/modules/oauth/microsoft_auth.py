#!/usr/bin/env python3

"""
Module for Microsoft (Entra ID / Azure AD) OAuth authentication.

Uses the MSAL library for the Authorization Code flow with PKCE and
delegates state management, identity resolution, and session handling
to the shared ``oauth_utils`` helpers.
"""

import os
import secrets
from typing import Any, Dict, Tuple, Union

import msal
from flask import redirect, request, jsonify, make_response

from pollenisator.core.components.logger_config import logger
from pollenisator.server.modules.oauth.oauth_utils import (
    build_login_response,
    confirm_link,
    generate_pkce_pair,
    pop_oauth_state,
    resolve_or_create_user,
    store_oauth_state,
)

ErrorStatus = Tuple[str, int]

# ---------------------------------------------------------------------------
# Configuration (environment variables)
# ---------------------------------------------------------------------------

MICROSOFT_CLIENT_ID = os.environ.get("MICROSOFT_CLIENT_ID", "")
MICROSOFT_CLIENT_SECRET = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
MICROSOFT_REDIRECT_URI = os.environ.get(
    "MICROSOFT_REDIRECT_URI",
    "http://localhost:5000/api/v1/auth/microsoft/callback",
)
MICROSOFT_TENANT_ID = os.environ.get("MICROSOFT_TENANT_ID", "common")
MICROSOFT_ALLOWED_DOMAIN = os.environ.get("MICROSOFT_ALLOWED_DOMAIN", "")

AUTHORITY = f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}"

SCOPES = ["User.Read"]  # Microsoft Graph basic profile


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_configured() -> bool:
    return bool(MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET)


def _get_msal_app() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        MICROSOFT_CLIENT_ID,
        authority=AUTHORITY,
        client_credential=MICROSOFT_CLIENT_SECRET,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def microsoft_login() -> Union[Any, ErrorStatus]:
    """Initiate Microsoft OAuth login (``GET /auth/microsoft/login``)."""
    if not _is_configured():
        return "Microsoft authentication is not configured on this server", 503

    app = _get_msal_app()

    state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce_pair()
    store_oauth_state(state, code_verifier)

    auth_url = app.get_authorization_request_url(
        scopes=SCOPES,
        state=state,
        redirect_uri=MICROSOFT_REDIRECT_URI,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    return redirect(auth_url)


def microsoft_callback(code: str = "", state: str = "") -> Union[Any, ErrorStatus]:
    """Handle the OAuth callback from Microsoft (``GET /auth/microsoft/callback``)."""
    if not _is_configured():
        return "Microsoft authentication is not configured on this server", 503

    # --- validate state / PKCE -----------------------------------------------
    state_from_request = request.args.get("state", "")
    if not state_from_request:
        logger.warning("Microsoft OAuth callback missing state parameter")
        return "Invalid state parameter", 400

    state_record = pop_oauth_state(state_from_request)
    if state_record is None:
        return "Invalid or expired state parameter", 400

    code_verifier = state_record.get("code_verifier")
    auth_code = request.args.get("code", "")
    if not auth_code:
        error = request.args.get("error", "unknown")
        error_desc = request.args.get("error_description", "")
        logger.warning("Microsoft OAuth error: %s – %s", error, error_desc)
        return f"Authentication failed: {error}", 401

    app = _get_msal_app()

    try:
        # --- exchange code for tokens ----------------------------------------
        result = app.acquire_token_by_authorization_code(
            auth_code,
            scopes=SCOPES,
            redirect_uri=MICROSOFT_REDIRECT_URI,
            code_verifier=code_verifier,
        )

        if "error" in result:
            logger.error(
                "Microsoft token error: %s – %s",
                result.get("error"),
                result.get("error_description", ""),
            )
            return f"Authentication error: {result.get('error_description', result['error'])}", 401

        id_token_claims = result.get("id_token_claims", {})

        email = (
            id_token_claims.get("email")
            or id_token_claims.get("preferred_username", "")
        )
        oid = id_token_claims.get("oid", "")  # unique Microsoft user id
        given_name = id_token_claims.get("given_name", "")
        family_name = id_token_claims.get("family_name", "")
        name = id_token_claims.get("name", "")

        if not email:
            logger.warning("Microsoft auth: no email claim in ID token")
            return "No email address returned by Microsoft", 401

        # --- domain restriction ----------------------------------------------
        if MICROSOFT_ALLOWED_DOMAIN:
            domain = email.split("@")[-1] if "@" in email else ""
            if domain.lower() != MICROSOFT_ALLOWED_DOMAIN.lower():
                logger.warning(
                    "User %s not from allowed domain %s", email, MICROSOFT_ALLOWED_DOMAIN
                )
                return f"Access restricted to {MICROSOFT_ALLOWED_DOMAIN} domain", 403

        # --- resolve user ----------------------------------------------------
        user_info = {
            "given_name": given_name or name.split(" ")[0] if name else "",
            "family_name": family_name or (" ".join(name.split(" ")[1:]) if name else ""),
            "picture": "",  # Microsoft Graph doesn't return picture in ID token
        }
        user, link_payload = resolve_or_create_user(email, "microsoft", oid, user_info)

        if link_payload is not None:
            return make_response(jsonify(link_payload), 200)

        if user is None:
            return "Failed to create or retrieve user account", 500

        logger.info("User %s (%s) logged in via Microsoft", user["username"], email)
        return build_login_response(user)

    except Exception as e:
        logger.error("Microsoft authentication error: %s", e)
        return f"Authentication error: {str(e)}", 500


def microsoft_link_confirm(body: Dict[str, str], **kwargs: Any) -> Union[Any, ErrorStatus]:
    """Confirm linking a Microsoft identity (``POST /auth/microsoft/link/confirm``)."""
    return confirm_link(body, **kwargs)


def get_microsoft_auth_status() -> Dict[str, Any]:
    """Get the current status of Microsoft authentication configuration."""
    return {
        "enabled": _is_configured(),
        "domain_restriction": bool(MICROSOFT_ALLOWED_DOMAIN),
        "allowed_domain": MICROSOFT_ALLOWED_DOMAIN if MICROSOFT_ALLOWED_DOMAIN else None,
    }
