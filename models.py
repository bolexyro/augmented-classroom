from pydantic import BaseModel
from datetime import timedelta


class Student(BaseModel):
    matric_number: str
    password: str


class TokenData(BaseModel):
    matric_number: str
    # i don't want to use this since JWTError already takes care of the expiry of the jwt token
    expire_time: timedelta | None = None


class RefreshToken(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str | None = None
    token_type: str
    refresh_token: str | None = None
    new_access_token: str | None = None
