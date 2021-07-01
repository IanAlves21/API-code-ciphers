from sanic import Blueprint
from .route_example import example
from .AES import aes
from .DES import des

routes = Blueprint.group([example, aes, des])
