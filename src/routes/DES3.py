from sanic.request import Request
from sanic.response import json
from sanic import Blueprint

from src.controllers import DES3

des3 = Blueprint('des3')

@des3.middleware('request')
async def middleware(request: Request):
    pass

@des3.post('/encrypt/des3')
async def encrypt(request: Request):
    return await DES3().encrypt(request)

@des3.post('/decrypt/des3')
async def encrypt(request: Request):
    return await DES3().decrypt(request)

# @des3.options('/')
# async def options(request: Request):
#     return json(None)
