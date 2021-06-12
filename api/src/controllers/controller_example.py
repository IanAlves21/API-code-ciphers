from sanic.request import Request
from sanic.response import json
# from peewee import DoesNotExist
# from src.models.user import User
from playhouse.shortcuts import model_to_dict
from datetime import timedelta, datetime
# from src.utils.environments import env
# from src.utils.database import postgres

import bcrypt
import jwt

class ClassExample:
    async def example_function(self, request: Request):
        print("called example function from example controller")

        return json({'message': "called example function from example controller"})
