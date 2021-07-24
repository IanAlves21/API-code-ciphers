from sanic import Blueprint
from .route_example import example
from .AES import aes
from .DES import des
from .DES3 import des3
from .IDEA import idea
from .Blowfish import blowfish
from .Twofish import twofish
from .EncryptTxtFile import encryptTxtFile

routes = Blueprint.group([example, aes, des, des3, idea, blowfish, twofish, encryptTxtFile])
