from sanic import Blueprint
from .route_example import example
from .AES import aes

routes = Blueprint.group([example, aes])
