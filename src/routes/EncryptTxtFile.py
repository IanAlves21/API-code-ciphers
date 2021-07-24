from sanic.request import Request
from sanic.response import json
from sanic import Blueprint

from src.controllers import EncryptTxtFile

encryptTxtFile = Blueprint('encryptTxtFile')

@encryptTxtFile.middleware('request')
async def middleware(request: Request):
    pass

@encryptTxtFile.post('/encrypt/txtfile')
async def encrypt(request: Request):
    return await EncryptTxtFile().encrypt(request)

@encryptTxtFile.post('/decrypt/txtfile')
async def encrypt(request: Request):
    return await EncryptTxtFile().decrypt(request)

# @encryptTxtFile.options('/')
# async def options(request: Request):
#     return json(None)
