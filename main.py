from fastapi import FastAPI, HTTPException, Request, status, Depends, Form
from fastapi.security import OAuth2PasswordBearer
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

db = os.getenv("DB_NAME")
db_username = os.getenv("DB_USERNAME")
db_password = os.getenv("DB_PASSWORD")
db_host = os.getenv("DB_INTERNAL_HOST")
db_port = os.getenv("DB_PORT")
origin = os.getenv("ORIGIN")
rp_id = os.getenv("RP_ID")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: Annotated[int,
                                       "Number of minutes the access token is valid for. I am setting it to 5 minutes"] = 5

connection_params = {"database": db,
                     "user": db_username,
                     "host": db_host,
                     "password": db_password,
                     "port": db_port}


app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


class Student(BaseModel):
    matric_number: str
    password: str


@app.get(path="/")
def home():
    return True


@app.post(path="/create-student")
def create_user(student: Student):
    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            select_student_info_from_students_table = "SELECT matric_number, password FROM students WHERE matric_number = %s"
            cursor.execute(select_student_info_from_students_table,
                           (student.matric_number.upper(), ))
            result = cursor.fetchone()
    if not result:
        insert_new_student_info_into_students_table_sql = "INSERT INTO students(matric_number, password) VALUES (%s, %s)"
        cursor.execute(insert_new_student_info_into_students_table_sql,
                       (student.matric_number.upper(), student.password))
        connection.commit()
        response_data = {"message": "Student created."}
        return JSONResponse(status_code=status.HTTP_200_OK, content=response_data)
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={
                        "message": "Student already exists."})


def create_access_refresh_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.post(path="/login")
# mosh is going to send the matric number and email as form data now
def get_user(username: Annotated[str, Form(title="The matric number of the student.")], password: Annotated[str, Form(title="The password of the student")]):
    # to follow the specs of oauth2, that is why i am using username
    matric_number = username
    incorrent_credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"message": "Incorrent matric number or password."},
        headers={"WWW-Authenticate": "Bearer"},
    )

    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            select_user_info_from_students_table = "SELECT matric_number, password FROM students WHERE matric_number = %s"
            cursor.execute(select_user_info_from_students_table,
                           (matric_number.upper(), ))
            result = cursor.fetchone()
    if result:
        retrieved_matric_number, retrieved_password = result
        if retrieved_password != password:
            raise incorrent_credentials_exception
        access_token_expires = timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_refresh_token(
            data={"sub": matric_number}, expires_delta=access_token_expires)
        return JSONResponse(status_code=status.HTTP_200_OK, content={"access_token": access_token, "token_type": "bearer"})
    raise incorrent_credentials_exception


class TokenData(BaseModel):
    matric_number: str
    # i don't want to use this since JWTError already takes care of the expiry of the jwt token
    expire_time: timedelta | None = None


async def decode_and_validate_token(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        matric_number: str = payload.get("sub")
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
    return result[0]


@app.get(path="/generate-registration-options")
def handler_generate_registration_options(matric_number: Annotated[str, Depends(decode_and_validate_token)]):
    user_id: int = random.randint(1, 1000000)
    registration_challenge: bytes = os.urandom(32)

    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            update_students_table_sql = "UPDATE students SET user_id = %s, registration_challenge = %s WHERE matric_number = %s;"
            cursor.execute(update_students_table_sql,
                           (user_id, registration_challenge, matric_number))
            connection.commit()

    options = generate_registration_options(
        rp_id=rp_id,
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
async def handler_verify_registration_response(request: Request, matric_number: Annotated[str, Depends(decode_and_validate_token)]):
    credential: dict = await request.json()  # returns a json object

    select_user_info_from_students_table_sql = "SELECT registration_challenge FROM students WHERE matric_number = %s"
    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                select_user_info_from_students_table_sql, (matric_number, ))
            result = cursor.fetchone()
    if not result:
        response_data = {"message": "matric number not found."}
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=response_data)
    registration_challenge: bytes = bytes(result[0])

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=registration_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
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
def handler_generate_authentication_options(matric_number: Annotated[str, Depends(decode_and_validate_token)]):
    authentication_challenge: bytes = os.urandom(32)

    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            select_user_info_from_students_table_sql = "SELECT credential_id, transports FROM students WHERE matric_number = %s"
            cursor.execute(
                select_user_info_from_students_table_sql, (matric_number, ))
            result = cursor.fetchone()

            if not result:
                response_data = {"message": "matric_number not found."}
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=response_data)

            credential_id, transports = result
            credential_id: bytes = bytes(credential_id)
            insert_auth_challenge_into_students_table_sql = "UPDATE students SET authentication_challenge = %s WHERE matric_number = %s"
            cursor.execute(insert_auth_challenge_into_students_table_sql,
                           (authentication_challenge, matric_number))
            connection.commit()
    if transports:
        transports = transports.split(",")

    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            {"type": "public-key", "id": credential_id, "transports": transports}
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
        challenge=authentication_challenge
    )

    return options_to_json(options)


@app.post("/verify-authentication-response")
async def hander_verify_authentication_response(matric_number: Annotated[str, Depends(decode_and_validate_token)], request: Request):
    try:
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
            response_data = {"message": "matric_number not found."}
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=response_data)
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
            expected_rp_id=rp_id,
            expected_origin=origin,
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
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    access_token_matric_number = decode_and_validate_token(access_token)
    refresh_token_matric_number = decode_and_validate_token(refresh_token)
    if refresh_token_matric_number != access_token_matric_number:
        raise credentials_exception
    token_data = TokenData(matric_number=access_token_matric_number)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_refresh_token(
        data={"sub": token_data.username}, expires_delta=access_token_expires
    )
    return {"new_access_token": new_access_token, "token_type": "bearer", "refresh_token": refresh_token.refresh_token}

uvicorn.run(app=app, host="0.0.0.0")
