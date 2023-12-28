from fastapi import FastAPI, HTTPException, Request, status, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
# The name of the module crud is app.crud. So, when we do fron .utils import models, we are telling it to go up one directory from app.crud to app and then access the module models there
import app.crud as crud
from app.database import engine
from app.models import StudentPydanticModel, RefreshToken, TokenResponse, StudentUpdateModel
from app.utils import create_access_refresh_token, decode_and_validate_token, verify_password, oauth2_scheme, credentials_exception, incorrent_matric_number_or_password_exception
from app.webauthn_functions import generate_registration_options_function, verify_registration_options_function, generate_authentication_options_functions, verify_authentication_options_function
from sqlmodel import Session
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import uvicorn
from dotenv import load_dotenv
from typing import Annotated
from datetime import timedelta
import uuid
from webauthn import options_to_json, base64url_to_bytes
load_dotenv(".env")

WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN")
CORS_ORIGIN = os.getenv("CORS_ORIGIN")
RP_ID = os.getenv("RP_ID")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: Annotated[int,
                                       "Number of minutes the access token is valid for. I am setting it to 15 minutes"] = float(os.getenv("ACCESS_TOKEN_DURATION"))
REFRESH_TOKEN_EXPIRE_MINUTES: Annotated[int,
                                        "I am setting the refresh token time to 4hrs"] = 240

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[CORS_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(path="/")
def home():
    return True


def get_session():
    with Session(engine) as session:
        yield session


GetSessionDep = Annotated[Session, Depends(get_session)]
ExtractTokenDep = Annotated[str, Depends(oauth2_scheme)]
token_auth_scheme = HTTPBearer()
HTTPExtractTokenDep = Annotated[HTTPAuthorizationCredentials, Depends(
    token_auth_scheme)]


# @app.post(path="/create-student", dependencies=[Depends(verify_token_for_create_student_endpoint)])
@app.post(path="/create-student")
async def create_student(*, session: GetSessionDep, student: StudentPydanticModel, authorization: HTTPExtractTokenDep):
    token = authorization.credentials
    if await decode_and_validate_token(token=token, token_expected="create_student_token"):
        db_student = crud.create_student(session, student)
        if db_student:
            student.password = "sike, you thought you were getting the original thing"
            return student.model_dump(exclude_unset=True)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Student already exists.")


@app.post(path="/verify-student", response_model=TokenResponse)
# mosh is going to send the matric number and email as form data now
# def get_user(username: Annotated[str, Form(title="The matric number of the student.")], password: Annotated[str, Form(title="The password of the student")]):
def verify_student(student: StudentPydanticModel, session: GetSessionDep):
    # to follow the specs of oauth2, that is why i am using username
    # matric_number = username

    db_student = crud.get_student(session, student.matric_number)
    if not db_student:
        raise incorrent_matric_number_or_password_exception
    retrieved_password: Annotated[str,
                                  "The hashed password"] = db_student.password
    if not verify_password(student.password, retrieved_password):
        # Wrong password
        raise incorrent_matric_number_or_password_exception
    access_token_expires = timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_refresh_token(
        data={"sub": "access|" + db_student.matric_number}, expires_delta=access_token_expires)

    refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_token = create_access_refresh_token(
        data={"sub": "refresh|" + db_student.matric_number}, expires_delta=refresh_token_expires)

    return TokenResponse(access_token=access_token, token_type="bearer", refresh_token=refresh_token)

# This registration challenge and authentication challenge, they are meant to be used just once. So I think i am going to delete them from the database
# and just store them in a dict
registration_challenges: dict[Annotated[str, "The matric number of a student"], Annotated[bytes, "The registration challenge associated with that user"]] = {}

@app.get(path="/generate-registration-options")
async def handler_generate_registration_options(*, matric_number: str, session: GetSessionDep, authorization: HTTPExtractTokenDep):
    token = authorization.credentials
    # decode_and_validate_token here can only return True if anything wrong happens it raises a credential error
    validated = await decode_and_validate_token(token=token, token_expected="create_student_token")
    user_id: uuid.UUID = uuid.uuid4()
    registration_challenge: bytes = os.urandom(32)
    update_data = StudentUpdateModel(
        user_id=user_id)
    registration_challenges[matric_number] = registration_challenge
    crud.update_student(session, matric_number, update_data)
    options = generate_registration_options_function(
        RP_ID=RP_ID, user_id=user_id, matric_number=matric_number, registration_challenge=registration_challenge)

    return options_to_json(options)


@app.post(path="/verify-registration-response")
async def handler_verify_registration_response(*, matric_number: str, request: Request, session: GetSessionDep, authorization: HTTPExtractTokenDep):
    token = authorization.credentials
    validated = await decode_and_validate_token(token=token, token_expected="create_student_token")

    credential: dict = await request.json()  # returns a json object
    registration_challenge = registration_challenges[matric_number]

    verification, transports_string = verify_registration_options_function(
        credential=credential, registration_challenge=registration_challenge, RP_ID=RP_ID, WEBAUTHN_ORIGIN=WEBAUTHN_ORIGIN)
    update_data = StudentUpdateModel(credential_id=verification.credential_id, public_key=verification.credential_public_key,
                                     sign_count=verification.sign_count, transports=transports_string)
    crud.update_student(session, matric_number, update_data)
    del registration_challenges[matric_number]
    return JSONResponse(status_code=status.HTTP_200_OK, content={"verified": True})


authentication_challenges: dict[Annotated[str, "The matric number of a student"], Annotated[bytes, "The authentication challenge associated with that user"]] = {}

@app.get(path="/generate-authentication-options")
async def handler_generate_authentication_options(session: GetSessionDep, token: ExtractTokenDep):
    matric_number = await decode_and_validate_token(token=token, session=session)
    authentication_challenge: bytes = os.urandom(32)

    db_student = crud.get_student(session, matric_number)
    # we are pretty much assuming that all these thigns have a non null value in the database
    credential_id, transports = db_student.credential_id, db_student.transports

    authentication_challenges[matric_number] = authentication_challenge
    options = generate_authentication_options_functions(
        RP_ID=RP_ID, credential_id=credential_id, transports=transports, authentication_challenge=authentication_challenge)

    return options_to_json(options)


@app.post("/verify-authentication-response", response_class=JSONResponse)
async def hander_verify_authentication_response(*, request: Request, session: GetSessionDep, token: ExtractTokenDep):

    matric_number = await decode_and_validate_token(token=token, session=session)
    credential: dict = await request.json()  # returns a json object
    # Find the user's corresponding public key
    raw_id_bytes: bytes = base64url_to_bytes(credential["rawId"])

    db_student = crud.get_student(session, matric_number)
    # We are assuming that when we are calling this endpoint all this info would be available in the datbase. like the stuent would have already registered
    credential_id, public_key, sign_count = db_student.credential_id, db_student.public_key, db_student.sign_count
    authentication_challenge = authentication_challenges[matric_number]

    verification = verify_authentication_options_function(credential_id=credential_id, raw_id_bytes=raw_id_bytes, credential=credential,
                                                          authentication_challenge=authentication_challenge, public_key=public_key, sign_count=sign_count, RP_ID=RP_ID, WEBAUTHN_ORIGIN=WEBAUTHN_ORIGIN)
    # Update our credential's sign count to what the authenticator says it is now
    crud.update_student(session, matric_number, StudentUpdateModel(
        sign_count=verification.new_sign_count))

    return JSONResponse(content={"verified": True}, status_code=status.HTTP_200_OK)


@app.post(path="/refresh")
async def refresh(refresh_token: RefreshToken, access_token: ExtractTokenDep, session: GetSessionDep):
    refresh_token_str = refresh_token.refresh_token
    # we are passing the session argument as well as the token explicitly because unlike those endpoint or path operations head, this is a regular calling of a function and FastAPi isn't helping us with any dependency injection
    access_matric_number = await decode_and_validate_token(access_token, session)
    refresh_matric_number = await decode_and_validate_token(refresh_token_str, session, token_expected="refresh")
    if not refresh_matric_number or not access_matric_number or refresh_matric_number != access_matric_number:
        raise credentials_exception
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_refresh_token(
        data={"sub": "access|" + access_matric_number}, expires_delta=access_token_expires
    )
    return TokenResponse(new_access_token=new_access_token, token_type="bearer").model_dump(exclude_unset=True)

if __name__ == "__main__":
    uvicorn.run(app=app, host="0.0.0.0")
