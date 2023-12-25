from sqlmodel import SQLModel, Field
from pydantic import BaseModel
from uuid import UUID


class BaseStudent(SQLModel):
    matric_number: str = Field(primary_key=True, max_length=15, min_length=5)
    password: str
    credential_id: bytes | None = None
    public_key: bytes | None = None
    sign_count: int | None = None
    user_id: UUID | None = None
    transports: str | None = None
    registration_challenge: bytes | None = None
    authentication_challenge: bytes | None = None


class StudentSQLModel(BaseStudent, table=True):
    pass


class StudentPydanticModel(BaseStudent):
    # I am making this one the same as BaseStudent in case of the future and we need to do something specially to StudentCreate
    pass


class RefreshToken(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str | None = None
    token_type: str
    refresh_token: str | None = None
    new_access_token: str | None = None
