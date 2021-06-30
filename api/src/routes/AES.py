from sanic.request import Request
from sanic.response import json
from sanic import Blueprint

from src.controllers import AES

aes = Blueprint('aes', url_prefix='/encrypt')

@aes.middleware('request')
async def middleware(request: Request):
    pass

@aes.post('/aes')
async def encrypt(request: Request):
    return await AES().encrypt(request)

@aes.options('/')
async def options(request: Request):
    return json(None)
