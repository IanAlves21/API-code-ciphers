from sanic.request import Request
from sanic.response import json
from sanic import Blueprint

from src.controllers import ClassExample

example = Blueprint('content', url_prefix='/example')

@example.middleware('request')
async def middleware(request: Request):
    pass

@example.post('/router_link')
async def store(request: Request):
    return await ClassExample().example_function(request)

@example.options('/')
async def options(request: Request):
    return json(None)
