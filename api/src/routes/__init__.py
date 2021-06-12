from sanic import Blueprint
from .route_example import example

routes = Blueprint.group([example])
