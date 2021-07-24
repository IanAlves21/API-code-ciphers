from sanic.request import Request
from sanic.response import json
from sanic import Blueprint

from src.controllers import AES

aes = Blueprint('aes')

@aes.middleware('request')
async def middleware(request: Request):
    pass

@aes.post('/encrypt/aes')
async def encrypt(request: Request):
    return await AES().encrypt(request)

@aes.post('/decrypt/aes')
async def encrypt(request: Request):
    return await AES().decrypt(request)

@aes.options('/')
async def options(request: Request):
    return json(None)
