from sanic.request import Request
from sanic.response import json
from sanic import Blueprint

from src.controllers import IDEA

idea = Blueprint('idea')

@idea.middleware('request')
async def middleware(request: Request):
    pass

@idea.post('/encrypt/idea')
async def encrypt(request: Request):
    return await IDEA().encrypt(request)

@idea.post('/decrypt/idea')
async def encrypt(request: Request):
    return await IDEA().decrypt(request)

# @idea.options('/')
# async def options(request: Request):
#     return json(None)
