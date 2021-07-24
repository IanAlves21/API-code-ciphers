from sanic import Sanic
from sanic.request import Request
from sanic.response import file
from sanic_cors import CORS
from secure import SecureHeaders
# from asyncio import AbstractEventLoop

from src.routes import routes
# from src.utils.database import postgres
# from peewee import IntegrityError, ProgrammingError
# from src.models import *

# import json

app = Sanic(__name__)
CORS(app)
app.blueprint(routes)

@app.middleware('response')
async def set_headers(request, response):
    SecureHeaders().sanic(response)

@app.get('/favicon.ico')
async def icon(request: Request):
    return await file('favicon.ico')
