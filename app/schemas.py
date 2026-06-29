from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    email: str
    displayName: str = Field(default="", max_length=120)
    authHash: str = Field(min_length=32, max_length=256)
    kdfSalt: str = Field(min_length=12, max_length=128)
    kdfIterations: int = Field(ge=200_000, le=2_000_000)
    publicKey: str = Field(min_length=64, max_length=8192)
    encryptedPrivateKey: dict[str, Any]


class LoginRequest(BaseModel):
    email: str
    authHash: str = Field(min_length=32, max_length=256)
    totpCode: Optional[str] = Field(default=None, max_length=12)


class TotpConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class FolderRequest(BaseModel):
    encryptedName: dict[str, Any]


class ItemRequest(BaseModel):
    folderId: Optional[int] = None
    collectionId: Optional[int] = None
    encryptedPayload: dict[str, Any]


class CollectionRequest(BaseModel):
    encryptedName: dict[str, Any]
    encryptedCollectionKey: str = Field(min_length=32, max_length=16384)


class MemberRequest(BaseModel):
    email: str
    role: str = Field(pattern="^(admin|member|read_only)$")
    encryptedCollectionKey: str = Field(min_length=32, max_length=16384)


class AdminUserPatch(BaseModel):
    isAdmin: Optional[bool] = None
    isDisabled: Optional[bool] = None


class SettingsPatch(BaseModel):
    registrationEnabled: bool

