"""API Key management functions with security best practices."""

from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone
import logging
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.logger_config import logger
from .api_key_model import ApiKey

class ApiKeyManager:
    """Manages API key operations with security considerations."""
    
    def __init__(self):
        self.collection_name = 'api_keys'
        self.dbclient = DBClient.getInstance()
        # Ensure indexes for performance and security
        self._ensure_indexes()
    
    def _ensure_indexes(self):
        """Create indexes for performance and security."""
        try:
            # Create indexes on the pollenisator database
            self.dbclient.create_index("pollenisator", self.collection_name, [("user_id", 1), ("is_active", 1)])
            self.dbclient.create_index("pollenisator", self.collection_name, [("expires_at", 1)])
            # Note: key_hash index would be unique but may cause issues during development
        except Exception as e:
            logger.warning(f"Could not create API key indexes: {e}")
    
    def create_api_key(self, user_id: str, name: str, expires_in_days: int,
                      permissions: List[str] = None, pentest: Optional[str] = None) -> Tuple[ApiKey, str]:
        """
        Create a new API key for a user.
        
        Args:
            user_id: User identifier
            name: Human-readable name for the key
            expires_in_days: Days until expiration (1-365)
            permissions: List of permissions
            pentest: Optional pentest UUID to restrict this key to a single pentest
        
        Returns:
            Tuple of (ApiKey instance, plain_api_key)
        """
        # Validate input
        if not 1 <= expires_in_days <= 365:
            raise ValueError("expires_in_days must be between 1 and 365")
        
        if not name or len(name.strip()) == 0:
            raise ValueError("name is required")
        
        if len(name) > 100:
            raise ValueError("name must be 100 characters or less")
        
        # Check if user already has an API key with this name
        existing = self.dbclient.findInDb("pollenisator", self.collection_name, {
            'user_id': user_id,
            'name': name,
            'is_active': True
        }, False)
        
        if existing:
            raise ValueError(f"Active API key with name '{name}' already exists")
        
        # Create the API key
        api_key_instance, plain_key = ApiKey.create(
            user_id=user_id,
            name=name,
            expires_in_days=expires_in_days,
            permissions=permissions or ['read'],
            pentest=pentest
        )
        
        # Store in database
        try:
            self.dbclient.insertInDb("pollenisator", self.collection_name, api_key_instance.to_dict())
            logger.info(f"Created API key {api_key_instance.key_id} for user {user_id}")
            return api_key_instance, plain_key
        except Exception as e:
            logger.error(f"Failed to create API key: {e}")
            raise RuntimeError("Failed to create API key")
    
    def verify_api_key(self, api_key: str) -> Optional[ApiKey]:
        """
        Verify an API key and return the associated user info.
        
        Args:
            api_key: The plain API key to verify
            
        Returns:
            ApiKey instance if valid, None otherwise
        """
        if not api_key:
            return None
        
        # Find all active keys and check against each one
        # This approach prevents timing attacks through database queries
        active_keys = self.dbclient.findInDb("pollenisator", self.collection_name, {
            'is_active': True,
            'expires_at': {'$gt': datetime.now(timezone.utc)}
        }, multi=True)
        
        if not active_keys:
            return None
            
        for key_doc in active_keys:
            api_key_instance = ApiKey.from_dict(key_doc)
            
            if ApiKey.verify_api_key(api_key, api_key_instance.salt, api_key_instance.key_hash):
                # Update last used timestamp
                api_key_instance.update_last_used()
                self.dbclient.updateInDb("pollenisator", self.collection_name,
                    {'_id': api_key_instance.key_id},
                    {'$set': {'last_used_at': api_key_instance.last_used_at}}, False
                )
                logger.info(f"API key {api_key_instance.key_id} used by user {api_key_instance.user_id}")
                return api_key_instance
        
        logger.warning("Invalid API key used")
        return None
    
    def list_user_api_keys(self, user_id: str) -> List[Dict[str, Any]]:
        """
        List all API keys for a user (excluding sensitive data).
        
        Args:
            user_id: User identifier
            
        Returns:
            List of API key information dictionaries
        """
        keys = self.dbclient.findInDb("pollenisator", self.collection_name, 
            {'user_id': user_id}, multi=True)
        
        if not keys:
            return []
        
        result = []
        for key_doc in keys:
            api_key = ApiKey.from_dict(key_doc)
            result.append(api_key.to_info_dict())
        
        # Sort by creation date, newest first
        result.sort(key=lambda x: x['created_at'], reverse=True)
        return result
    
    def revoke_api_key(self, user_id: str, key_id: str) -> bool:
        """
        Revoke an API key for a user.
        
        Args:
            user_id: User identifier
            key_id: API key identifier
            
        Returns:
            True if revoked, False if not found
        """
        result = self.dbclient.updateInDb("pollenisator", self.collection_name,
            {'_id': key_id, 'user_id': user_id},
            {'$set': {'is_active': False}}, False
        )
        
        if result.modified_count > 0:
            logger.info(f"Revoked API key {key_id} for user {user_id}")
            return True
        
        return False

    def remove_api_key(self, user_id: str, key_id: str) -> bool:
        """
        Remove an API key from the database.
        
        Args:
            user_id: User identifier
            key_id: API key identifier
        Returns:
            True if removed, False if not found
        """
        result = self.dbclient.deleteFromDb("pollenisator", self.collection_name,
            {'_id': key_id, 'user_id': user_id}
        )
        
        if result > 0:
            logger.info(f"Removed API key {key_id} for user {user_id}")
            return True
        return False

    
    def cleanup_expired_keys(self):
        """Clean up expired API keys."""
        result = self.dbclient.updateInDb("pollenisator", self.collection_name,
            {
                'expires_at': {'$lt': datetime.now(timezone.utc)},
                'is_active': True
            },
            {'$set': {'is_active': False}}, True  # many=True
        )
        
        if result.modified_count > 0:
            logger.info(f"Deactivated {result.modified_count} expired API keys")
