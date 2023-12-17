from fastapi import FastAPI, HTTPException, Request, status, Depends, Form
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import random
import os
import psycopg2
import uvicorn
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import Annotated
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement
)
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes
)

load_dotenv(".env")

DB = os.getenv("DB_NAME")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_EXTERNAL_HOST")
DB_PORT = os.getenv("DB_PORT")
ORIGIN = os.getenv("ORIGIN")
RP_ID = os.getenv("RP_ID")
SECRET_KEY = os.getenv("SECRET_KEY")
SECRET_MESSAGE = os.getenv("SECRET_MESSAGE")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: Annotated[int,
                                       "Number of minutes the access token is valid for. I am setting it to 15 minutes"] = 15
REFRESH_TOKEN_EXPIRE_MINUTES: Annotated[int,
                                        "I am setting the refresh token time to 4hrs"] = 240

connection_params = {"database": DB,
                     "user": DB_USERNAME,
                     "host": DB_HOST,
                     "password": DB_PASSWORD,
                     "port": DB_PORT}


app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=[ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="verify-student")
token_auth_scheme = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Student(BaseModel):
    matric_number: str
    password: str


@app.get(path="/")
def home():
    return True


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Function to verify a password


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


async def verify_token_for_create_student_endpoint(authorization: Annotated[HTTPAuthorizationCredentials, Depends(token_auth_scheme)]):
    token = authorization.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        message: str = payload.get("sub")
        if message is None or message != SECRET_MESSAGE:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return True


@app.post(path="/create-student")
def create_user(student: Student, token_is_verified: Annotated[bool, Depends(verify_token_for_create_student_endpoint)]):
    if token_is_verified:
        hashed_password = get_password_hash(student.password)
        with psycopg2.connect(**connection_params) as connection:
            with connection.cursor() as cursor:
                select_student_info_from_students_table = "SELECT matric_number, password FROM students WHERE matric_number = %s"
                cursor.execute(select_student_info_from_students_table,
                               (student.matric_number.upper(), ))
                result = cursor.fetchone()
                if not result:
                    insert_new_student_info_into_students_table_sql = "INSERT INTO students(matric_number, password) VALUES (%s, %s)"
                    cursor.execute(insert_new_student_info_into_students_table_sql,
                                   (student.matric_number.upper(), hashed_password))
                    connection.commit()
                    response_data = {"message": "Student created."}
                    return JSONResponse(status_code=status.HTTP_200_OK, content=response_data)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Student already exists.")


def create_access_refresh_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.post(path="/verify-student")
# mosh is going to send the matric number and email as form data now
# def get_user(username: Annotated[str, Form(title="The matric number of the student.")], password: Annotated[str, Form(title="The password of the student")]):
def get_user(student: Student):
    # to follow the specs of oauth2, that is why i am using username
    # matric_number = username
    matric_number = student.matric_number
    password = student.password
    incorrent_credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrent matric number or password.")

    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            select_user_info_from_students_table = "SELECT matric_number, password FROM students WHERE matric_number = %s"
            cursor.execute(select_user_info_from_students_table,
                           (matric_number.upper(), ))
            result = cursor.fetchone()
    if result:
        retrieved_matric_number, retrieved_password = result
        retrieved_password: Annotated[str,
                                      "The hashed password"] = retrieved_password
        if not verify_password(password, retrieved_password):
            raise incorrent_credentials_exception

        access_token_expires = timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_refresh_token(
            data={"sub": "access|" + matric_number}, expires_delta=access_token_expires)

        refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
        refresh_token = create_access_refresh_token(
            data={"sub": "refresh|" + matric_number}, expires_delta=refresh_token_expires)

        return JSONResponse(status_code=status.HTTP_200_OK, content={"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token})
    raise incorrent_credentials_exception


class TokenData(BaseModel):
    matric_number: str
    # i don't want to use this since JWTError already takes care of the expiry of the jwt token
    expire_time: timedelta | None = None


async def decode_and_validate_token(token: Annotated[str, Depends(oauth2_scheme)]) -> list[Annotated[str, "Whether or not the token is an access or refresh"], Annotated[str, "The matric number of the user"]]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload: dict[str, str] = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM])
        access_or_refresh_token: Annotated[str, "access if it is an access token else refresh"] = payload.get(
            "sub").split("|")[0]
        matric_number: str = payload.get("sub").split("|")[1]
        if matric_number is None:
            raise credentials_exception
        token_data = TokenData(matric_number=matric_number)
    except JWTError:
        raise credentials_exception
    # idk if there is a point of validating if the matric number exists since we alredy did that before the token was created.
    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            select_user_info_from_students_table = "SELECT matric_number FROM students WHERE matric_number = %s"
            cursor.execute(select_user_info_from_students_table,
                           (token_data.matric_number.upper(), ))
            result: list[Annotated[str, "The matric number"]
                         ] = cursor.fetchone()
    if not result:
        raise credentials_exception
    return [access_or_refresh_token, result[0]]


@app.get(path="/generate-registration-options")
def handler_generate_registration_options(token_type_and_matric_number: Annotated[list[str, str], Depends(decode_and_validate_token)]):
    token_type, matric_number = token_type_and_matric_number
    user_id: int = random.randint(1, 1000000)
    registration_challenge: bytes = os.urandom(32)

    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            update_students_table_sql = "UPDATE students SET user_id = %s, registration_challenge = %s WHERE matric_number = %s;"
            cursor.execute(update_students_table_sql,
                           (user_id, registration_challenge, matric_number))
            connection.commit()

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name="Augmented Classroom",
        user_id=str(user_id),
        user_name=matric_number,
        user_display_name=matric_number,
        attestation=AttestationConveyancePreference.DIRECT,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
        challenge=registration_challenge,
        exclude_credentials=[],
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        timeout=60000
    )

    return options_to_json(options)


@app.post(path="/verify-registration-response")
async def handler_verify_registration_response(request: Request, token_type_and_matric_number: Annotated[list[str, str], Depends(decode_and_validate_token)]):
    token_type, matric_number = token_type_and_matric_number
    credential: dict = await request.json()  # returns a json object

    select_user_info_from_students_table_sql = "SELECT registration_challenge FROM students WHERE matric_number = %s"
    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                select_user_info_from_students_table_sql, (matric_number, ))
            result = cursor.fetchone()
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="matric number not found.")
    registration_challenge: bytes = bytes(result[0])

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=registration_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )

    except Exception as err:
        print(err)

    # I am meant to store the credential and the user attached to this credential

    transports: list = credential["response"]["transports"]
    transports_string: str = ""
    lenght_transports: int = len(transports)
    for i, transport in enumerate(transports):
        transports_string += transport
        if i != lenght_transports - 1:
            transports_string += ","

    update_students_table_sql = "UPDATE students SET credential_id = %s, public_key = %s, sign_count = %s, transports = %s WHERE matric_number = %s"
    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            cursor.execute(update_students_table_sql, (verification.credential_id,
                           verification.credential_public_key, verification.sign_count, transports_string, matric_number))
            connection.commit()

    return JSONResponse(status_code=status.HTTP_200_OK, content={"verified": True})


@app.get(path="/generate-authentication-options")
def handler_generate_authentication_options(token_type_and_matric_number: Annotated[list[str, str], Depends(decode_and_validate_token)]):
    token_type, matric_number = token_type_and_matric_number
    authentication_challenge: bytes = os.urandom(32)

    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            select_user_info_from_students_table_sql = "SELECT credential_id, transports FROM students WHERE matric_number = %s"
            cursor.execute(
                select_user_info_from_students_table_sql, (matric_number, ))
            result = cursor.fetchone()

            if not result:

                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="matric_number not found.")

            credential_id, transports = result
            credential_id: bytes = bytes(credential_id)
            insert_auth_challenge_into_students_table_sql = "UPDATE students SET authentication_challenge = %s WHERE matric_number = %s"
            cursor.execute(insert_auth_challenge_into_students_table_sql,
                           (authentication_challenge, matric_number))
            connection.commit()
    if transports:
        transports = transports.split(",")

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            {"type": "public-key", "id": credential_id, "transports": transports}
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
        challenge=authentication_challenge
    )

    return options_to_json(options)


@app.post("/verify-authentication-response")
async def hander_verify_authentication_response(request: Request, token_type_and_matric_number: Annotated[list[str, str], Depends(decode_and_validate_token)]):
    try:
        token_type, matric_number = token_type_and_matric_number
        credential: dict = await request.json()  # returns a json object
        # Find the user's corresponding public key
        raw_id_bytes: bytes = base64url_to_bytes(credential["rawId"])
        with psycopg2.connect(**connection_params) as connection:
            with connection.cursor() as cursor:
                select_user_info_from_students_table_sql = "SELECT credential_id, authentication_challenge, public_key, sign_count FROM students WHERE matric_number = %s"
                cursor.execute(
                    select_user_info_from_students_table_sql, (matric_number, ))
                result = cursor.fetchone()

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="matric_number not found.")
        credential_id, authentication_challenge, public_key, sign_count = result

        credential_id: bytes = bytes(credential_id)
        authentication_challenge: bytes = bytes(authentication_challenge)
        public_key: bytes = bytes(public_key)

        user_credential = None
        if credential_id == raw_id_bytes:
            user_credential = True  # we could set it to anything as long as it is not None

        if user_credential is None:
            raise Exception("Could not find corresponding public key in DB")

        # Verify the assertion
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=authentication_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )
        # Update our credential's sign count to what the authenticator says it is now
        with psycopg2.connect(**connection_params) as connection:
            with connection.cursor() as cursor:
                update_user_sign_count_in_students_table_sql = "UPDATE students SET sign_count = %s WHERE matric_number=%s"
                cursor.execute(update_user_sign_count_in_students_table_sql,
                               (verification.new_sign_count, matric_number))
                connection.commit()

    except Exception as err:
        print(err)
        response_data = {"verified": False, "msg": str(err)}
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=response_data)

    return JSONResponse(content={"verified": True}, status_code=status.HTTP_200_OK)


class RefreshToken(BaseModel):
    refresh_token: str


@app.post(path="/refresh")
async def refresh(refresh_token: RefreshToken, access_token: Annotated[str, Depends(oauth2_scheme)]):
    refresh_token_str = refresh_token.refresh_token
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    is_this_an_access_token, access_matric_number = await decode_and_validate_token(access_token)
    is_this_a_refresh_token, refresh_matric_number = await decode_and_validate_token(refresh_token_str)
    if not refresh_matric_number or not access_matric_number or refresh_matric_number != access_matric_number or is_this_a_refresh_token != "refresh" or is_this_an_access_token != "access":
        raise credentials_exception
    token_data = TokenData(matric_number=access_matric_number)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_refresh_token(
        data={"sub": "access|" + token_data.matric_number}, expires_delta=access_token_expires
    )
    return {"new_access_token": new_access_token, "token_type": "bearer"}

uvicorn.run(app=app, host="0.0.0.0")
