from sanic.request import Request
from sanic.response import json
from sanic import Blueprint

from src.controllers import DES

des = Blueprint('des')

@des.middleware('request')
async def middleware(request: Request):
    pass

@des.post('/encrypt/des')
async def encrypt(request: Request):
    return await DES().encrypt(request)

@des.post('/decrypt/des')
async def encrypt(request: Request):
    return await DES().decrypt(request)

# @des.options('/')
# async def options(request: Request):
#     return json(None)
