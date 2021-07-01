from sanic.request import Request
from sanic.response import json
from sanic import Blueprint

from src.controllers import Blowfish

blowfish = Blueprint('blowfish')

@blowfish.middleware('request')
async def middleware(request: Request):
    pass

@blowfish.post('/encrypt/blowfish')
async def encrypt(request: Request):
    return await Blowfish().encrypt(request)

@blowfish.post('/decrypt/blowfish')
async def encrypt(request: Request):
    return await Blowfish().decrypt(request)

# @blowfish.options('/')
# async def options(request: Request):
#     return json(None)
