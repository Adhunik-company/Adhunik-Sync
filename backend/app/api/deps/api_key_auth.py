from datetime import datetime
from typing import Optional, List, Annotated
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlmodel import Session, select

from app.models import ApiKey, User, ScopeType
from app.api.deps import get_db, SessionDep

# API key header configuration
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_api_key(
    session: SessionDep,
    api_key_header: str = Security(API_KEY_HEADER),
) -> Optional[ApiKey]:
    """
    Validate the API key from header and return the associated ApiKey object.
    Returns None if no API key was provided or if the key is invalid.
    """
    if not api_key_header:
        return None
    
    # In a real implementation, you would hash the API key before querying
    # This is a simplified version for demonstration
    query = select(ApiKey).where(ApiKey.key == api_key_header)
    api_key = session.exec(query).first()
    
    if not api_key:
        return None
    
    # Check if key is active, not revoked, and not expired
    if (
        not api_key.is_active
        or api_key.revoked
        or (api_key.expires_at and api_key.expires_at < datetime.utcnow())
    ):
        return None
    
    # Update last used timestamp
    api_key.last_used_at = datetime.utcnow()
    session.add(api_key)
    session.commit()
    
    return api_key


async def get_api_key_user(
    session: SessionDep,
    api_key: Optional[ApiKey] = Depends(get_api_key),
) -> Optional[User]:
    """
    Get the user associated with the API key.
    Returns None if no valid API key was provided.
    """
    if not api_key:
        return None
    
    query = select(User).where(User.id == api_key.owner_id)
    user = session.exec(query).first()
    
    return user


def require_api_key_with_scopes(required_scopes: List[ScopeType]):
    """
    Dependency factory that requires a valid API key with specific scopes.
    Usage: Depends(require_api_key_with_scopes([ScopeType.ACCOUNTS_READ]))
    """
    
    async def validate_api_key_scopes(
        api_key: Optional[ApiKey] = Depends(get_api_key),
    ) -> ApiKey:
        # Ensure API key is provided and valid
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        
        # Check if the API key has all required scopes
        api_key_scopes = set(api_key.scopes)
        for scope in required_scopes:
            if scope not in api_key_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key missing required scope: {scope.value}",
                )
        
        return api_key
    
    return validate_api_key_scopes


# Common dependencies for specific scope combinations
require_accounts_read = require_api_key_with_scopes([ScopeType.ACCOUNTS_READ])
require_accounts_write = require_api_key_with_scopes([ScopeType.ACCOUNTS_WRITE])
require_webhooks_read = require_api_key_with_scopes([ScopeType.WEBHOOKS_READ])
require_webhooks_write = require_api_key_with_scopes([ScopeType.WEBHOOKS_WRITE])
