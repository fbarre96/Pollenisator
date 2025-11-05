"""API Key database model for secure API authentication."""

import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Tuple
from bson import ObjectId


class ApiKey:
    """API Key model with security best practices."""
    
    def __init__(self, key_id: str, user_id: str, name: str, key_hash: str, 
                 salt: str, created_at: datetime, expires_at: datetime,
                 last_used_at: Optional[datetime], permissions: List[str], 
                 is_active: bool):
        self.key_id = key_id
        self.user_id = user_id
        self.name = name
        self.key_hash = key_hash  # Store hash, not plain key
        self.salt = salt
        self.created_at = created_at
        self.expires_at = expires_at
        self.last_used_at = last_used_at
        self.permissions = permissions
        self.is_active = is_active
    
    @classmethod
    def generate_api_key(cls) -> Tuple[str, str, str]:
        """
        Generate a secure API key with salt and hash.
        Returns: (api_key, salt, key_hash)
        """
        # Generate a cryptographically secure random key
        api_key = secrets.token_urlsafe(32)  # 256 bits of entropy
        salt = secrets.token_hex(16)  # 128-bit salt
        
        # Hash the key with salt using SHA-256
        key_hash = hashlib.sha256((api_key + salt).encode()).hexdigest()
        
        return api_key, salt, key_hash
    
    @classmethod
    def verify_api_key(cls, api_key: str, salt: str, stored_hash: str) -> bool:
        """Verify an API key against stored hash and salt."""
        computed_hash = hashlib.sha256((api_key + salt).encode()).hexdigest()
        # Use secrets.compare_digest for timing attack resistance
        return secrets.compare_digest(computed_hash, stored_hash)
    
    @classmethod
    def create(cls, user_id: str, name: str, expires_in_days: int, 
               permissions: List[str]) -> Tuple['ApiKey', str]:
        """
        Create a new API key instance.
        Returns: (ApiKey instance, plain_api_key)
        """
        api_key, salt, key_hash = cls.generate_api_key()
        
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=expires_in_days)
        
        instance = cls(
            key_id=str(ObjectId()),
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            salt=salt,
            created_at=now,
            expires_at=expires_at,
            last_used_at=None,
            permissions=permissions or ['read'],
            is_active=True
        )
        
        return instance, api_key
    
    def is_expired(self) -> bool:
        """Check if the API key has expired."""
        now = datetime.now(timezone.utc)
        expires_at = self.expires_at
        
        # Ensure expires_at has timezone info for comparison
        if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
            
        return now > expires_at
    
    def is_valid(self) -> bool:
        """Check if the API key is valid (active and not expired)."""
        return self.is_active and not self.is_expired()
    
    def update_last_used(self):
        """Update the last used timestamp."""
        self.last_used_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            '_id': self.key_id,
            'user_id': self.user_id,
            'name': self.name,
            'key_hash': self.key_hash,
            'salt': self.salt,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'last_used_at': self.last_used_at,
            'permissions': self.permissions,
            'is_active': self.is_active
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ApiKey':
        """Create instance from dictionary."""
        # Ensure datetime objects have timezone info
        created_at = data['created_at']
        if isinstance(created_at, datetime) and created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
            
        expires_at = data['expires_at'] 
        if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
            
        last_used_at = data.get('last_used_at')
        if last_used_at and isinstance(last_used_at, datetime) and last_used_at.tzinfo is None:
            last_used_at = last_used_at.replace(tzinfo=timezone.utc)
            
        return cls(
            key_id=data['_id'],
            user_id=data['user_id'],
            name=data['name'],
            key_hash=data['key_hash'],
            salt=data['salt'],
            created_at=created_at,
            expires_at=expires_at,
            last_used_at=last_used_at,
            permissions=data['permissions'],
            is_active=data['is_active']
        )
    
    def to_info_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses (excluding sensitive data)."""
        return {
            'key_id': self.key_id,
            'name': self.name,
            'created_at': self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            'expires_at': self.expires_at.isoformat() if isinstance(self.expires_at, datetime) else self.expires_at,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at and isinstance(self.last_used_at, datetime) else self.last_used_at,
            'permissions': self.permissions,
            'is_active': self.is_valid()
        }
