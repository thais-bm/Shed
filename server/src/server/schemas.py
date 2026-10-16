from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(..., min_length=6, max_length=128)
    public_identity_key: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class UserPublic(BaseModel):
    username: str
    public_identity_key: str | None = None
    created_at: str


class FriendInfo(BaseModel):
    username: str
    status: str
    direction: str  # "sent", "received" ou "accepted"
    updated_at: str


class FriendsListResponse(BaseModel):
    friends: list[str]
    pending_received: list[str]
    pending_sent: list[str]
