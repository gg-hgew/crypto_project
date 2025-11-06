from fastapi import FastAPI
from encryption import rsa_encrypt_decrypt, aes_encrypt_decrypt
from pydantic import BaseModel

app = FastAPI()


class EncryptRequest(BaseModel):
    message: str
    method: str


@app.post("/encrypt")
def encrypt(request: EncryptRequest):
    if request.method == "RSA":
        return rsa_encrypt_decrypt(request.message)
    elif request.method == "AES":
        return aes_encrypt_decrypt(request.message)
    else:
        return {"error": "Unknown method"}
