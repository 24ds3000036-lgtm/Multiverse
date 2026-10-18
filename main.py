# -*- coding: utf-8 -*-
"""
Created on Sun Oct 18 15:07:20 2026

@author: Home
"""

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import jwt

app = FastAPI()

# Assigned values from the prompt
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-udhdaez9.apps.exam.local"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY----"""

class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
def verify_token(payload: TokenRequest):
    try:
        # Decode and validate signature, issuer, audience, and expiration automatically
        claims = jwt.decode(
            payload.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "verify_signature": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_exp": True,
            }
        )
        
        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud")
        }
        
    except jwt.PyJWTError:
        # Reject any invalid token (signature failure, expired, wrong aud/iss, tampered)
        return {"valid": False}