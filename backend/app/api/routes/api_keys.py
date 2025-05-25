from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlmodel import select

from app.models import (
    ApiKey, 
    ApiKeyCreate, 
    ApiKeyPublic, 
    ApiKeyResponse, 
    ApiKeysPublic,
    ScopeType
)
from app.api.deps.auth import CurrentUser, SessionDep
from app.core.config import settings

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@router.post("", response_model=ApiKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    api_key_data: ApiKeyCreate,
    current_user: CurrentUser,
    session: SessionDep,
):
    """
    Create a new API key for the current user.
    
    - **name**: A descriptive name for the API key
    - **scopes**: List of scopes this key will have access to
    - **expiry_days**: Number of days until the key expires (1-365)
    """
    # Generate key, prefix and hash
    key, key_prefix, hashed_key = ApiKey.generate_key()
    
    # Calculate expiry date
    expires_at = datetime.utcnow() + timedelta(days=api_key_data.expiry_days)
    
    # Create API key object
    db_api_key = ApiKey(
        name=api_key_data.name,
        key=key,  # Note: In a production system, you wouldn't store the raw key
        key_prefix=key_prefix,
        hashed_key=hashed_key,
        owner_id=current_user.id,
        scopes=api_key_data.scopes,
        expires_at=expires_at,
        created_at=datetime.utcnow(),
    )
    session.add(db_api_key)
    session.commit()
    session.refresh(db_api_key)
    
    # Return the full API key in the response
    # This is the only time the full key will be shown
    return ApiKeyResponse(
        id=db_api_key.id,
        name=db_api_key.name,
        key=key,  # Include the actual key in the response
        key_prefix=db_api_key.key_prefix,
        scopes=db_api_key.scopes,  # Directly use the scopes list
        created_at=db_api_key.created_at,
        expires_at=db_api_key.expires_at,
    )


@router.get("", response_model=ApiKeysPublic)
async def list_api_keys(
    current_user: CurrentUser,
    session: SessionDep,
    skip: int = 0,
    limit: int = 100,
    show_expired: bool = False,
    show_revoked: bool = False,
):
    """
    List all API keys for the current user.
    
    - **skip**: Number of records to skip (pagination)
    - **limit**: Maximum number of records to return
    - **show_expired**: Include expired keys in results
    - **show_revoked**: Include revoked keys in results
    """
    query = select(ApiKey).where(ApiKey.owner_id == current_user.id)
    
    # Filter out expired keys unless explicitly requested
    if not show_expired:
        query = query.where(
            (ApiKey.expires_at > datetime.utcnow()) | (ApiKey.expires_at.is_(None))
        )
    
    # Filter out revoked keys unless explicitly requested
    if not show_revoked:
        query = query.where(ApiKey.revoked == False)
    
    # Apply pagination
    query = query.offset(skip).limit(limit)
    
    # Execute query
    api_keys = session.exec(query).all()
    
    # Count total (without pagination)
    from sqlalchemy import func
    count_query = select(func.count()).select_from(ApiKey).where(ApiKey.owner_id == current_user.id)
    if not show_expired:
        count_query = count_query.where(
            (ApiKey.expires_at > datetime.utcnow()) | (ApiKey.expires_at.is_(None))
        )
    if not show_revoked:
        count_query = count_query.where(ApiKey.revoked == False)
    
    total_count = session.exec(count_query).one()
    
    # Transform to public view
    public_keys = [
        ApiKeyPublic(
            id=key.id,
            name=key.name,
            key_prefix=key.key_prefix,
            scopes=key.scopes,  # Directly use the scopes list
            created_at=key.created_at,
            expires_at=key.expires_at,
            is_active=key.is_active and not key.revoked and (key.expires_at is None or key.expires_at > datetime.utcnow()),
            last_used_at=key.last_used_at,
        )
        for key in api_keys
    ]
    
    return ApiKeysPublic(data=public_keys, count=total_count)


@router.get("/{api_key_id}", response_model=ApiKeyPublic)
async def get_api_key(
    api_key_id: str,
    current_user: CurrentUser,
    session: SessionDep,
):
    """
    Get details of a specific API key.
    """
    # Find the API key
    query = select(ApiKey).where(
        ApiKey.id == api_key_id, 
        ApiKey.owner_id == current_user.id
    )
    api_key = session.exec(query).first()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    
    # Transform to public view
    return ApiKeyPublic(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
        is_active=api_key.is_active and not api_key.revoked and (api_key.expires_at is None or api_key.expires_at > datetime.utcnow()),
        last_used_at=api_key.last_used_at,
    )


@router.delete("/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    api_key_id: str,
    current_user: CurrentUser,
    session: SessionDep,
):
    """
    Revoke an API key. This operation cannot be undone.
    """
    # Find the API key
    query = select(ApiKey).where(
        ApiKey.id == api_key_id, 
        ApiKey.owner_id == current_user.id
    )
    api_key = session.exec(query).first()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    
    # Revoke the key
    api_key.revoked = True
    api_key.revoked_at = datetime.utcnow()
    api_key.is_active = False
    
    session.add(api_key)
    session.commit()
    
    # No content response
    return None
