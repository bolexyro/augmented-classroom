import app.crud as crud
from fastapi import FastAPI, HTTPException, Request, status, Depends
from app.models import StudentPydanticModel, RefreshToken, TokenResponse, StudentUpdateModel
from app.database import engine
from sqlmodel import Session
from app.utils import create_access_refresh_token, verify_password, verify_token_for_create_student_endpoint, oauth2_scheme, credentials_exception, incorrent_matric_number_or_password_exception
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import uvicorn
from dotenv import load_dotenv
from typing import Annotated
from datetime import timedelta
from jose import JWTError, jwt
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
import uuid
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


@app.post(path="/create-student", dependencies=[Depends(verify_token_for_create_student_endpoint)])
def create_student(*, session: Session = Depends(get_session), student: StudentPydanticModel):
    db_student = crud.create_student(session, student)
    if db_student:
        response_data = {"message": "Student created."}
        return JSONResponse(status_code=status.HTTP_200_OK, content=response_data)
    raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                        detail="Student already exists.")


@app.post(path="/verify-student", response_model=TokenResponse)
# mosh is going to send the matric number and email as form data now
# def get_user(username: Annotated[str, Form(title="The matric number of the student.")], password: Annotated[str, Form(title="The password of the student")]):
def verify_student(student: StudentPydanticModel, session: Session = Depends(get_session)):
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


async def decode_and_validate_token(token: Annotated[str, Depends(oauth2_scheme)], session: Session = Depends(get_session)) -> list[Annotated[str, "Whether or not the token is an access or refresh"], Annotated[str, "The matric number of the user"]]:
    try:
        payload: dict[str, str] = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM])
        access_or_refresh_token: Annotated[str, "access if it is an access token else refresh"] = payload.get(
            "sub").split("|")[0]
        matric_number: str = payload.get("sub").split("|")[1]
        if matric_number is None:
            raise credentials_exception
    except (JWTError, IndexError):
        raise credentials_exception
    # idk if there is a point of validating if the matric number exists since we alredy did that before the token was created.
    db_student = crud.get_student(session, matric_number)
    if not db_student:
        raise credentials_exception
    return [access_or_refresh_token, db_student.matric_number]

DecodeValidateTokenDep = Annotated[list[str,
                                        str], Depends(decode_and_validate_token)]


@app.get(path="/generate-registration-options")
def handler_generate_registration_options(*, session: Session = Depends(get_session), token_type_and_matric_number: DecodeValidateTokenDep):
    try:
        matric_number = token_type_and_matric_number[1]
        user_id: uuid.UUID = uuid.uuid4()
        registration_challenge: bytes = os.urandom(32)
        update_data = StudentUpdateModel(
            user_id=user_id, registration_challenge=registration_challenge)
        crud.update_student(session, matric_number, update_data)
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
    except Exception as err:
        print("Error:", err)
    return options_to_json(options)


@app.post(path="/verify-registration-response")
async def handler_verify_registration_response(*, request: Request, session: Session = Depends(get_session), token_type_and_matric_number: DecodeValidateTokenDep):
    try:
        matric_number = token_type_and_matric_number[1]
        credential: dict = await request.json()  # returns a json object
        db_student = crud.get_student(session, matric_number)
        registration_challenge: bytes = bytes(
            db_student.registration_challenge)

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=registration_challenge,
            expected_rp_id=RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
        )
        # I am meant to store the credential and the user attached to this credential
        transports: list = credential["response"]["transports"]
        transports_string: str = ""
        lenght_transports: int = len(transports)
        for i, transport in enumerate(transports):
            transports_string += transport
            if i != lenght_transports - 1:
                transports_string += ","

        update_data = StudentUpdateModel(credential_id=verification.credential_id, public_key=verification.credential_public_key,
                                         sign_count=verification.sign_count, transports=transports_string)
        crud.update_student(session, matric_number, update_data)

    except Exception as err:
        print(err)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return JSONResponse(status_code=status.HTTP_200_OK, content={"verified": True})


@app.get(path="/generate-authentication-options")
def handler_generate_authentication_options(session: Annotated[Session, Depends(get_session)], token_type_and_matric_number: DecodeValidateTokenDep):
    try:
        matric_number = token_type_and_matric_number[1]
        authentication_challenge: bytes = os.urandom(32)

        db_student = crud.get_student(session, matric_number)
        credential_id, transports = db_student.credential_id, db_student.transports
        credential_id: bytes = bytes(credential_id)

        crud.update_student(session, matric_number, StudentUpdateModel(
            authentication_challenge=authentication_challenge))
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
    except Exception as err:
        print("Error:", err)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return options_to_json(options)


@app.post("/verify-authentication-response", response_class=JSONResponse)
async def hander_verify_authentication_response(*, request: Request, session: Session = Depends(get_session), token_type_and_matric_number: DecodeValidateTokenDep):
    try:
        matric_number = token_type_and_matric_number[1]
        credential: dict = await request.json()  # returns a json object
        # Find the user's corresponding public key
        raw_id_bytes: bytes = base64url_to_bytes(credential["rawId"])

        db_student = crud.get_student(session, matric_number)
        credential_id, authentication_challenge, public_key, sign_count = db_student.credential_id, db_student.authentication_challenge, db_student.public_key, db_student.sign_count

        credential_id: bytes = bytes(credential_id)
        authentication_challenge: bytes = bytes(authentication_challenge)
        public_key: bytes = bytes(public_key)

        user_credential = None
        if credential_id == raw_id_bytes:
            user_credential = True  # we could set it to anything as long as it is not None

        if user_credential is None:
            raise Exception(
                "Could not find corresponding public key in DB")

        # Verify the assertion
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=authentication_challenge,
            expected_rp_id=RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )
        # Update our credential's sign count to what the authenticator says it is now
        crud.update_student(session, matric_number, StudentUpdateModel(
            sign_count=verification.new_sign_count))

    except Exception as err:
        print("Error:", err)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return JSONResponse(content={"verified": True}, status_code=status.HTTP_200_OK)


@app.post(path="/refresh")
async def refresh(refresh_token: RefreshToken, access_token: Annotated[str, Depends(oauth2_scheme)], session: Session = Depends(get_session)):
    refresh_token_str = refresh_token.refresh_token
    # we are passing the session argument as well as the token explicitly because unlike those endpoint or path operations head, this is a regular calling of a function and FastAPi isn't helping us with any dependency injection
    is_this_an_access_token, access_matric_number = await decode_and_validate_token(access_token, session)
    is_this_a_refresh_token, refresh_matric_number = await decode_and_validate_token(refresh_token_str, session)
    if not refresh_matric_number or not access_matric_number or refresh_matric_number != access_matric_number or is_this_a_refresh_token != "refresh" or is_this_an_access_token != "access":
        raise credentials_exception
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_refresh_token(
        data={"sub": "access|" + access_matric_number}, expires_delta=access_token_expires
    )
    return TokenResponse(new_access_token=new_access_token, token_type="bearer")

if __name__ == "__main__":
    uvicorn.run(app=app, host="0.0.0.0")
