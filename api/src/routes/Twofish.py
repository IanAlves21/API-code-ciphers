from sanic.request import Request
from sanic.response import json
from sanic import Blueprint

from src.controllers import Twofish

twofish = Blueprint('twofish')

@twofish.middleware('request')
async def middleware(request: Request):
    pass

@twofish.post('/encrypt/twofish')
async def encrypt(request: Request):
    return await Twofish().encrypt(request)

@twofish.post('/decrypt/twofish')
async def encrypt(request: Request):
    return await Twofish().decrypt(request)

# @twofish.options('/')
# async def options(request: Request):
#     return json(None)
