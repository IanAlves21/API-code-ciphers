from sanic import Blueprint
from .route_example import example
from .AES import aes
from .DES import des
from .DES3 import des3

routes = Blueprint.group([example, aes, des, des3])
