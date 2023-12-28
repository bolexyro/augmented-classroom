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
    verify_authentication_response
)
from fastapi import HTTPException, status
from uuid import UUID


def generate_registration_options_function(RP_ID: str, user_id: UUID, matric_number: str, registration_challenge: bytes):
    try:
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return options


def verify_registration_options_function(credential: dict, registration_challenge: bytes, RP_ID: str, WEBAUTHN_ORIGIN: str):
    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=registration_challenge,
            expected_rp_id=RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
        )
        # I am meant to store the credential and the user attached to this credential
        transports: list = credential["response"]["transports"]
        transports_string: str = ""
        transports_string = ",".join(transports)
    except Exception as err:
        print(err)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return verification, transports_string


def generate_authentication_options_functions(RP_ID: str, credential_id: bytes, transports: str, authentication_challenge: bytes):
    try:
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
        return options
    except Exception as err:
        print("Error:", err)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


def verify_authentication_options_function(credential_id: bytes, raw_id_bytes: bytes, credential, authentication_challenge: bytes, public_key: bytes, sign_count, RP_ID: str, WEBAUTHN_ORIGIN: str):
    try:
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
    except Exception as err:
        print("Error:", err)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return verification
