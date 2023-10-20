from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import random
import json
import os
import psycopg2
import uvicorn
from dotenv import load_dotenv
from pydantic import BaseModel

from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
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

connection_params = {"database": db,
                     "user": db_username,
                     "host": db_host,
                     "password": db_password,
                     "port": db_port}

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Student(BaseModel):
    matric_number: str
    password: str


@app.get(path="/")
def home():
    return True


@app.post(path="/create-user")
def create_user(student: Student):
    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            select_user_info_from_students_table = "SELECT matric_number, password FROM students WHERE matric_number = %s"
            cursor.execute(select_user_info_from_students_table,
                           (student.matric_number, ))
            result = cursor.fetchone()
            if not result:
                insert_new_student_info_into_students_table_sql = "INSERT INTO students(matric_number, password) VALUES (%s, %s)"
                cursor.execute(insert_new_student_info_into_students_table_sql,
                               (student.matric_number, student.password))
                connection.commit()
                response_data = {"message": "Student created."}
                return JSONResponse(status_code=200, content=response_data)
            return JSONResponse(status_code=400, content={"message": "Student already exists."})


@app.get(path="/verify-user")
def get_user(matric_number: str, password: str):
    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            select_user_info_from_students_table = "SELECT matric_number, password FROM students WHERE matric_number = %s"
            cursor.execute(select_user_info_from_students_table,
                           (matric_number, ))
            result = cursor.fetchone()
            if not result:
                response_data = {"message": "matric number not found."}
                return JSONResponse(status_code=404, content=response_data)
            retrieved_matric_number, retrieved_password = result
            if retrieved_password != password:
                response_data = {"Incorrect password."}
                return JSONResponse(status_code=401, content=response_data)
            return JSONResponse(status_code=200, content={"message": "Login successful."})


@app.get(path="/generate-registration-options")
def handler_generate_registration_options(matric_number: str):
    user_id = random.randint(1, 1000000)
    registration_challenge = os.urandom(32)

    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            insert_into_students_table_sql = "INSERT INTO students (user_id, matric_number, registration_challenge) VALUES (%s, %s, %s)"
            cursor.execute(insert_into_students_table_sql,
                           (user_id, matric_number, registration_challenge))
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
        timeout=30000
    )

    return options_to_json(options)


@app.post(path="/verify-registration-response")
async def handler_veaify_registration_response(matric_number: str, request: Request):
    body = await request.json()  # returns a json object
    credential = json.dumps(body, indent=4)  # returns  json string
    credential = json.loads(credential)

    select_user_info_from_students_table_sql = "SELECT registration_challenge FROM students WHERE matric_number = %s"
    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                select_user_info_from_students_table_sql, (matric_number, ))
            result = cursor.fetchone()
            if not result:
                response_data = {"message": "matric number not found."}
                return JSONResponse(status_code=404, content=response_data)
            registration_challenge = result[0]

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=registration_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
    except Exception as err:
        raise HTTPException(status_code=400, detail=str(err))

    # I am meant to store the credential and the user attached to this credential

    transports: list = credential["response"]["transports"]
    transports_string = ""
    lenght_transports = len(transports)
    for i, transport in enumerate(transports):
        transports_string += transport
        if i != lenght_transports - 1:
            transports_string += ","

    insert_into_students_table_sql = "INSERT INTO students (credential_id, public_key, sign_count, transports) VALUES (%s, %s, %s, %s)"
    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            cursor.execute(insert_into_students_table_sql, (verification.credential.id,
                           verification.credential_public_key, verification.sign_count, transports_string))
            connection.commit()

    return JSONResponse(content={"verified": True})


@app.get(path="/generate-authentication-options")
def handler_generate_authentication_options(matric_number: str):
    authentication_challenge = os.urandom(32)

    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            select_user_info_from_students_table_sql = "SELECT credential_id, transports FROM students WHERE matric_number = %s"
            cursor.execute(
                select_user_info_from_students_table_sql, (matric_number, ))
            result = cursor.fetchone()

            if not result:
                response_data = {"message": "matric_number not found."}
                return JSONResponse(status_code=404, content=response_data)

            credential_id, transports = result
            insert_auth_challenge_into_students_table_sql = "INSERT INTO students (authentication_challenge) VALUES (%s) WHERE matric_number = %s"
            cursor.execute(insert_auth_challenge_into_students_table_sql,
                           (authentication_challenge, matric_number))
            connection.commit()

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
async def hander_verify_authentication_response(matric_number: str, request: Request):
    body = await request.json()  # returns a json object

    try:
        credential = json.dumps(body, indent=4)  # returns  json string
        credential = json.loads(credential)
        # Find the user's corresponding public key

        # Assuming credential["rawId"] is a base64url-encoded string
        raw_id_bytes = base64url_to_bytes(credential["rawId"])
        with psycopg2.connect(**connection_params) as connection:
            with connection.cursor() as cursor:
                select_user_info_from_students_table_sql = "SELECT credential_id, authentication_challenge, public_key, sign_count FROM students WHERE matric_number = %s"
                cursor.execute(
                    select_user_info_from_students_table_sql, (matric_number, ))
                result = cursor.fetchone()

                if not result:
                    response_data = {"message": "matric_number not found."}
                    return JSONResponse(status_code=404, content=response_data)
                credential_id, authentication_challenge, public_key, sign_count = result

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
        return {"verified": False, "msg": str(err), "status": 400}

    return {"verified": True}


uvicorn.run(app=app, host="0.0.0.0")
