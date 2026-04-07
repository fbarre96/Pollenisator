#!/usr/bin/env python3

"""
Shared utilities for OAuth providers (Google, Microsoft, etc.).

Provides common logic for:
- PKCE code_verifier / code_challenge generation
- CSRF state token storage & validation (Redis with MongoDB fallback)
- User identity resolution via the ``oauth_identities`` array
- Session-cookie helper used across auth endpoints
- Reverse-proxy–safe callback URL reconstruction
- Expired-state cleanup
"""

import base64
import datetime
import hashlib
import json
import os
import secrets
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlencode, urlparse, urlunparse

import bcrypt
from flask import Response, jsonify, make_response, request

from pollenisator.core.components.logger_config import logger
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.utils import JSONEncoder
from pollenisator.server.token import decode_token, getTokenFor

ErrorStatus = Tuple[str, int]

isdebug = bool(os.environ.get("FLASK_DEBUG", False))

# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------

def generate_pkce_pair() -> Tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` using S256."""
    code_verifier = secrets.token_urlsafe(96)
    code_challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    return code_verifier, code_challenge


# ---------------------------------------------------------------------------
# State storage (Redis → MongoDB fallback)
# ---------------------------------------------------------------------------

_STATE_TTL_SECONDS = 300  # 5 minutes

def store_oauth_state(state: str, code_verifier: str, extra: Optional[Dict[str, Any]] = None) -> None:
    """Persist a one-time CSRF *state* with its PKCE *code_verifier*.

    Storage priority: Redis (with 5-min TTL) → MongoDB ``oauth_states``.
    *extra* is merged into the persisted document (e.g. ``{"link_username": "..."}``).
    """
    dbclient = DBClient.getInstance()
    now = datetime.datetime.now()
    state_data: Dict[str, Any] = {
        "state": state,
        "code_verifier": code_verifier,
        "created_at": now,
        "expires_at": now + datetime.timedelta(seconds=_STATE_TTL_SECONDS),
    }
    if extra:
        state_data.update(extra)

    stored = False
    if dbclient.cacher.isAvailable() and dbclient.cacher.redis is not None:
        try:
            dbclient.cacher.redis.set(
                f"oauth_state.{state}",
                json.dumps(state_data, cls=JSONEncoder),
                ex=_STATE_TTL_SECONDS,
            )
            stored = True
        except Exception:
            pass
    if not stored:
        dbclient.insertInDb("pollenisator", "oauth_states", state_data)


def pop_oauth_state(state_token: str) -> Optional[Dict[str, Any]]:
    """Retrieve **and delete** the one-time *state_token*.

    Returns the state document or ``None`` if not found / expired.
    """
    dbclient = DBClient.getInstance()

    record: Optional[Dict[str, Any]] = None
    if dbclient.cacher.isAvailable() and dbclient.cacher.redis is not None:
        try:
            raw = dbclient.cacher.redis.get(f"oauth_state.{state_token}")
            if raw is not None:
                record = json.loads(raw)
                dbclient.cacher.redis.delete(f"oauth_state.{state_token}")
        except Exception:
            pass
    if record is None:
        record = dbclient.findInDb(
            "pollenisator", "oauth_states", {"state": state_token}, False
        )

    if record is None:
        logger.warning("OAuth state not found – possible CSRF or expiry")
        return None

    # Check expiry
    expires_at = record.get("expires_at")
    if isinstance(expires_at, datetime.datetime) and datetime.datetime.now() > expires_at:
        logger.warning("OAuth state expired")
        dbclient.deleteFromDb("pollenisator", "oauth_states", {"state": state_token}, False)
        return None

    # Delete (one-time use)
    dbclient.deleteFromDb("pollenisator", "oauth_states", {"state": state_token}, False)
    return record


# ---------------------------------------------------------------------------
# Callback URL reconstruction (reverse-proxy safe)
# ---------------------------------------------------------------------------

def build_callback_url(configured_redirect_uri: str) -> str:
    """Reconstruct the full callback URL using *configured_redirect_uri* parts
    combined with the current request's query parameters.

    This avoids problems when Flask sees an internal origin (``http://127.0.0.1:5000``)
    behind a reverse-proxy whereas the real origin is ``https://example.com``.
    """
    parts = urlparse(configured_redirect_uri)
    query_string = urlencode(request.args.to_dict())
    url = urlunparse((
        parts.scheme,
        parts.netloc,
        parts.path,
        "",
        query_string,
        "",
    ))
    logger.debug("Constructed authorization response URL: %s", url)
    return url


# ---------------------------------------------------------------------------
# Session cookie helper
# ---------------------------------------------------------------------------

def set_session_cookie(response: Response, token: str) -> Response:
    """Set the ``session_token`` httpOnly cookie on *response*."""
    response.set_cookie(
        "session_token",
        token,
        httponly=True,
        secure=not isdebug,
        samesite="Strict",
    )
    return response


# ---------------------------------------------------------------------------
# User identity resolution
# ---------------------------------------------------------------------------

def _find_user_by_identity(provider: str, provider_id: str) -> Optional[Dict[str, Any]]:
    """Lookup a user by an entry in their ``oauth_identities`` array."""
    dbclient = DBClient.getInstance()
    return dbclient.findInDb(
        "pollenisator",
        "users",
        {
            "oauth_identities": {
                "$elemMatch": {"provider": provider, "provider_id": provider_id}
            }
        },
        False,
        use_cache=False,
    )


def _find_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    dbclient = DBClient.getInstance()
    return dbclient.findInDb(
        "pollenisator", "users", {"email": email}, False, use_cache=False
    )


def _store_link_token(
    provider: str,
    provider_id: str,
    provider_email: str,
    matched_username: str,
    user_info: Dict[str, Any],
) -> str:
    """Create a short-lived token the frontend can use to confirm account linking."""
    temp_token = secrets.token_urlsafe(32)
    dbclient = DBClient.getInstance()
    now = datetime.datetime.now()
    link_data = {
        "temp_token": temp_token,
        "provider": provider,
        "provider_id": provider_id,
        "provider_email": provider_email,
        "matched_username": matched_username,
        "user_info": user_info,
        "created_at": now,
        "expires_at": now + datetime.timedelta(seconds=_STATE_TTL_SECONDS),
    }
    stored = False
    if dbclient.cacher.isAvailable() and dbclient.cacher.redis is not None:
        try:
            dbclient.cacher.redis.set(
                f"oauth_link.{temp_token}",
                json.dumps(link_data, cls=JSONEncoder),
                ex=_STATE_TTL_SECONDS,
            )
            stored = True
        except Exception:
            pass
    if not stored:
        dbclient.insertInDb("pollenisator", "oauth_link_tokens", link_data)
    return temp_token


def resolve_or_create_user(
    email: str,
    provider: str,
    provider_id: str,
    user_info: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Resolve an OAuth identity to a local user account.

    Returns ``(user_record, None)`` on direct match / auto-create,
    or ``(None, link_payload)`` when the frontend must ask the user to confirm linking.

    *user_info* must contain at least ``given_name``, ``family_name``, ``picture``.
    """
    # 1) Direct match via oauth_identities
    user = _find_user_by_identity(provider, provider_id)
    if user is not None:
        _update_last_login(user, provider, provider_id, user_info)
        return user, None

    # 2) Email match – identity not yet linked → ask frontend to confirm
    user = _find_user_by_email(email)
    if user is not None:
        temp_token = _store_link_token(
            provider, provider_id, email, user["username"], user_info
        )
        link_payload = {
            "action": "link_required",
            "temp_token": temp_token,
            "matched_username": user["username"],
            "matched_email": user.get("email", ""),
            "provider": provider,
            "provider_email": email,
            "expires_in": _STATE_TTL_SECONDS,
        }
        return None, link_payload

    # 3) No match at all → auto-create
    user = _auto_create_user(email, provider, provider_id, user_info)
    return user, None


def _auto_create_user(
    email: str,
    provider: str,
    provider_id: str,
    user_info: Dict[str, Any],
) -> Dict[str, Any]:
    dbclient = DBClient.getInstance()
    username = email

    # Handle username collisions
    existing = dbclient.findInDb("pollenisator", "users", {"username": username}, False)
    if existing is not None:
        username = f"{username}_{provider_id[:8]}"
        logger.info("Username conflict resolved, using: %s", username)

    identity_entry = {
        "provider": provider,
        "provider_id": provider_id,
        "email": email,
    }

    user_data: Dict[str, Any] = {
        "username": username,
        "email": email,
        "name": user_info.get("given_name", ""),
        "surname": user_info.get("family_name", ""),
        "picture": user_info.get("picture", ""),
        "oauth_identities": [identity_entry],
        "mustChangePassword": False,
        "scope": ["user"],
        "created_via": f"{provider}_oauth",
        "created_at": datetime.datetime.now(),
    }

    dbclient.insertInDb("pollenisator", "users", user_data)
    logger.info("Auto-created user %s via %s OAuth", username, provider)
    return dbclient.findInDb("pollenisator", "users", {"username": username}, False, use_cache=False)


def _update_last_login(
    user: Dict[str, Any],
    provider: str,
    provider_id: str,
    user_info: Dict[str, Any],
) -> None:
    dbclient = DBClient.getInstance()
    update: Dict[str, Any] = {
        "last_login_provider": provider,
        "last_login": datetime.datetime.now(),
        "picture": user_info.get("picture", user.get("picture", "")),
    }
    dbclient.updateInDb(
        "pollenisator", "users", {"username": user["username"]}, {"$set": update}, False
    )


# ---------------------------------------------------------------------------
# Link-confirm (shared across providers)
# ---------------------------------------------------------------------------

def confirm_link(body: Dict[str, str], **kwargs: Any) -> Union[Response, ErrorStatus]:
    """Confirm linking an OAuth identity to an existing account.

    Called by ``POST /auth/{provider}/link/confirm``.

    Expects *body* with ``temp_token`` and ``password``.
    Returns the same session payload as a normal login on success.
    """
    temp_token = body.get("temp_token", "")
    password = body.get("password", "")
    if not temp_token or not password:
        return "temp_token and password are required", 400

    dbclient = DBClient.getInstance()

    # Retrieve link token
    link_data: Optional[Dict[str, Any]] = None
    if dbclient.cacher.isAvailable() and dbclient.cacher.redis is not None:
        try:
            raw = dbclient.cacher.redis.get(f"oauth_link.{temp_token}")
            if raw is not None:
                link_data = json.loads(raw)
                dbclient.cacher.redis.delete(f"oauth_link.{temp_token}")
        except Exception:
            pass
    if link_data is None:
        link_data = dbclient.findInDb(
            "pollenisator", "oauth_link_tokens", {"temp_token": temp_token}, False
        )
    if link_data is None:
        return "Link token not found or expired", 410

    # Check expiry
    expires_at = link_data.get("expires_at")
    if isinstance(expires_at, datetime.datetime) and datetime.datetime.now() > expires_at:
        dbclient.deleteFromDb("pollenisator", "oauth_link_tokens", {"temp_token": temp_token}, False)
        return "Link token expired, please restart the OAuth flow", 410

    # Delete one-time token
    dbclient.deleteFromDb("pollenisator", "oauth_link_tokens", {"temp_token": temp_token}, False)

    username = link_data["matched_username"]
    user = dbclient.findInDb("pollenisator", "users", {"username": username}, False, use_cache=False)
    if user is None:
        return "User not found", 404

    # Verify password (OAuth-only accounts have no hash → linking not possible for them)
    user_hash = user.get("hash")
    if user_hash is None:
        return "This account was created via OAuth and has no password. Please contact an administrator.", 400
    if not bcrypt.checkpw(password.encode(), user_hash):
        return "Incorrect password", 401

    # Append identity
    provider = link_data["provider"]
    provider_id = link_data["provider_id"]
    provider_email = link_data.get("provider_email", "")
    identity_entry = {
        "provider": provider,
        "provider_id": provider_id,
        "email": provider_email,
    }
    dbclient.updateInDb(
        "pollenisator",
        "users",
        {"username": username},
        {"$push": {"oauth_identities": identity_entry}},
        False,
    )

    # Update last login
    user_info = link_data.get("user_info", {})
    _update_last_login(user, provider, provider_id, user_info)

    # Issue JWT & session cookie
    token = getTokenFor(username)
    decoded = decode_token(token)

    response = make_response(
        jsonify(
            {
                "action": "logged_in",
                "mustChangePassword": user.get("mustChangePassword", False),
                "username": username,
                "email": user.get("email", ""),
                "name": f"{user.get('name', '')} {user.get('surname', '')}".strip(),
                "picture": user.get("picture", ""),
                "session_expiration": decoded.get("exp", 0),
                "scopes": decoded.get("scope", []),
            }
        )
    )
    return set_session_cookie(response, token)


def build_login_response(user: Dict[str, Any]) -> Response:
    """Build the standard JSON + cookie response for a successful OAuth login."""
    username = user["username"]
    token = getTokenFor(username)
    decoded = decode_token(token)

    response = make_response(
        jsonify(
            {
                "action": "logged_in",
                "mustChangePassword": False,
                "username": username,
                "email": user.get("email", ""),
                "name": f"{user.get('name', '')} {user.get('surname', '')}".strip(),
                "picture": user.get("picture", ""),
                "session_expiration": decoded.get("exp", 0),
                "scopes": decoded.get("scope", []),
            }
        )
    )
    return set_session_cookie(response, token)


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def cleanup_expired_oauth_states() -> int:
    """Delete expired state tokens from MongoDB.  Returns count deleted."""
    dbclient = DBClient.getInstance()
    now = datetime.datetime.now()
    expired = dbclient.findInDb(
        "pollenisator", "oauth_states", {"expires_at": {"$lt": now}}, True
    )
    count = 0
    if expired:
        for rec in expired:
            dbclient.deleteFromDb("pollenisator", "oauth_states", {"_id": rec["_id"]}, False)
            count += 1
    # Also clean link tokens
    expired_links = dbclient.findInDb(
        "pollenisator", "oauth_link_tokens", {"expires_at": {"$lt": now}}, True
    )
    if expired_links:
        for rec in expired_links:
            dbclient.deleteFromDb("pollenisator", "oauth_link_tokens", {"_id": rec["_id"]}, False)
            count += 1
    if count:
        logger.info("Cleaned up %d expired OAuth tokens", count)
    return count
