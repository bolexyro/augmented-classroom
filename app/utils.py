from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer
from typing import Annotated
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os
from sqlmodel import Session
from . import crud

load_dotenv(".env")

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
SECRET_MESSAGE = os.getenv("SECRET_MESSAGE")
SECRET_KEY = os.getenv("SECRET_KEY")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="verify-student")
token_auth_scheme = HTTPBearer()

incorrent_matric_number_or_password_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Incorrent matric number or password.")

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_refresh_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def decode_and_validate_token(token: str, session: Session | None = None , token_expected: str = "access") -> Annotated[str | bool, "The matric number of the user or True"]:
    from . import crud 
    try:
        if not session:
            print("hello world")
            assert token_expected == "create_student_token"
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            message: str = payload.get("sub")
            if message is None or message != SECRET_MESSAGE:
                raise credentials_exception
            return True
        payload: dict[str, str] = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM])
        access_or_refresh_token: Annotated[str, "access if it is an access token else refresh"] = payload.get(
            "sub").split("|")[0]
        matric_number: str = payload.get("sub").split("|")[1]
        if matric_number is None or access_or_refresh_token != token_expected:
            raise credentials_exception
    except (JWTError, IndexError):
        raise credentials_exception
    db_student = crud.get_student(session, matric_number)
    if not db_student:
        raise credentials_exception
    return db_student.matric_number
