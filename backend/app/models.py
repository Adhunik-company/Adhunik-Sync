import uuid
import secrets
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import List, Optional, Set

from pydantic import EmailStr, validator
from sqlmodel import Field, Relationship, SQLModel, Column, JSON


# Shared properties
class UserBase(SQLModel):
    email: EmailStr = Field(unique=True, index=True, max_length=255)
    is_active: bool = True
    is_superuser: bool = False
    full_name: str | None = Field(default=None, max_length=255)


# Properties to receive via API on creation
class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=40)


class UserRegister(SQLModel):
    email: EmailStr = Field(max_length=255)
    password: str = Field(min_length=8, max_length=40)
    full_name: str | None = Field(default=None, max_length=255)


# Properties to receive via API on update, all are optional
class UserUpdate(UserBase):
    email: EmailStr | None = Field(default=None, max_length=255)  # type: ignore
    password: str | None = Field(default=None, min_length=8, max_length=40)


class UserUpdateMe(SQLModel):
    full_name: str | None = Field(default=None, max_length=255)
    email: EmailStr | None = Field(default=None, max_length=255)


class UpdatePassword(SQLModel):
    current_password: str = Field(min_length=8, max_length=40)
    new_password: str = Field(min_length=8, max_length=40)


# Database model, database table inferred from class name
class User(UserBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    hashed_password: str
    items: list["Item"] = Relationship(back_populates="owner", cascade_delete=True)
    api_keys: list["ApiKey"] = Relationship(back_populates="owner", cascade_delete=True)


# Properties to return via API, id is always required
class UserPublic(UserBase):
    id: uuid.UUID


class UsersPublic(SQLModel):
    data: list[UserPublic]
    count: int


# Shared properties
class ItemBase(SQLModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=255)


# Properties to receive on item creation
class ItemCreate(ItemBase):
    pass


# Properties to receive on item update
class ItemUpdate(ItemBase):
    title: str | None = Field(default=None, min_length=1, max_length=255)  # type: ignore


# Database model, database table inferred from class name
class Item(ItemBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    owner_id: uuid.UUID = Field(
        foreign_key="user.id", nullable=False, ondelete="CASCADE"
    )
    owner: User | None = Relationship(back_populates="items")


# Properties to return via API, id is always required
class ItemPublic(ItemBase):
    id: uuid.UUID
    owner_id: uuid.UUID


class ItemsPublic(SQLModel):
    data: list[ItemPublic]
    count: int


# Generic message
class Message(SQLModel):
    message: str


# JSON payload containing access token
class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"


# Contents of JWT token
class TokenPayload(SQLModel):
    sub: str | None = None


class NewPassword(SQLModel):
    token: str
    new_password: str = Field(min_length=8, max_length=40)


# API Key models

class ScopeType(str, Enum):
    """Types of API scopes available"""
    ACCOUNTS_READ = "accounts:read"
    ACCOUNTS_WRITE = "accounts:write"
    WEBHOOKS_READ = "webhooks:read"
    WEBHOOKS_WRITE = "webhooks:write"


class ApiKeyBase(SQLModel):
    """Base model for API key"""
    name: str = Field(index=True, max_length=100)
    scopes: List[ScopeType] = Field(sa_column=Column(JSON))
    expires_at: datetime | None = None
    
    @validator("scopes")
    def validate_scopes(cls, v):
        """Ensure scopes are valid"""
        if not v:
            raise ValueError("At least one scope must be provided")
        
        valid_scopes = set(item.value for item in ScopeType)
        for scope in v:
            if scope not in valid_scopes:
                raise ValueError(f"Invalid scope: {scope}")
        return v


class ApiKeyCreate(ApiKeyBase):
    """Model for creating a new API key"""
    expiry_days: int = Field(ge=1, le=365, description="Number of days until key expires")
    
    @validator("expiry_days")
    def validate_expiry_days(cls, v):
        if v < 1 or v > 365:
            raise ValueError("Expiry days must be between 1 and 365")
        return v


class ApiKey(ApiKeyBase, table=True):
    """Database model for API keys"""
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    key: str = Field(unique=True, index=True)
    key_prefix: str = Field(max_length=8, index=True)  # Prefix for display/reference
    hashed_key: str  # Stores hashed version of the key for security
    
    owner_id: uuid.UUID = Field(foreign_key="user.id")
    owner: User = Relationship(back_populates="api_keys")
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used_at: datetime | None = None
    is_active: bool = True
    revoked: bool = False
    revoked_at: datetime | None = None
    
    @classmethod
    def generate_key(cls) -> tuple[str, str, str]:
        """Generate a new API key, its prefix, and hash"""
        # Generate a secure random key
        key = secrets.token_urlsafe(32)
        
        # Create a prefix for reference (first 8 chars)
        key_prefix = key[:8]
        
        # In a real app, you would hash this with a secure method
        # For this example, we'll use a simple representation
        hashed_key = f"hashed_{key}"
        
        return key, key_prefix, hashed_key


# Relationship is already defined in the User class
# No need to add it here


class ApiKeyPublic(SQLModel):
    """Public representation of an API key"""
    id: uuid.UUID
    name: str
    key_prefix: str
    scopes: List[str]
    created_at: datetime
    expires_at: datetime | None = None
    is_active: bool
    last_used_at: datetime | None = None


class ApiKeyResponse(SQLModel):
    """Response when creating a new API key"""
    id: uuid.UUID
    name: str
    key: str  # Full key - only shown once at creation
    key_prefix: str
    scopes: List[str]
    created_at: datetime
    expires_at: datetime | None = None


class ApiKeysPublic(SQLModel):
    """Response model for listing API keys"""
    data: List[ApiKeyPublic]
    count: int
