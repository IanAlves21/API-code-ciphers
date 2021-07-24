from sanic.request import Request
from sanic.response import json
# from playhouse.shortcuts import model_to_dict
# from datetime import timedelta, datetime
from .AES import AES
from .DES import DES
from .DES3 import DES3
from .IDEA import IDEA
from .Blowfish import Blowfish
from .Twofish import Twofish

# import bcrypt
# import jwt
import numpy as np
import os
import re

class EncryptTxtFile:
    async def encrypt(self, request: Request):
        arguments = request.form
        encrypted_message = ""
        algorithm_type = arguments["type"][0]
        key = arguments["key"][0]

        file_path = await self.saveFile(request.files.get('file'))
        file_data = await self.readFileData(file_path)

        file_data = re.sub(r'[^a-zA-Z\d\s]', u'', file_data)

        if(algorithm_type=="aes"):
            encrypted_message = await AES().encryptFileData(file_data, key)
        elif(algorithm_type=="des"):
            encrypted_message = await DES().encryptFileData(file_data, key)
        elif(algorithm_type=="des3"):
            key_size = arguments["key_size"][0]
            encrypted_message = await DES3().encryptFileData(file_data, key, int(key_size))
        elif(algorithm_type=="idea"):
            encrypted_message = await IDEA().encryptFileData(file_data, key)
        elif(algorithm_type=="blowfish"):
            encrypted_message = await Blowfish().encryptFileData(file_data, key)
        elif(algorithm_type=="twofish"):
            key_size = arguments["key_size"][0]
            encrypted_message = await Blowfish().encryptFileData(file_data, key, int(key_size))

        return json({"success": True, 'encrypted_message': encrypted_message})

    async def decrypt(self, request: Request):
        arguments = request.form
        decrypted_message = ""
        algorithm_type = arguments["type"][0]
        key = arguments["key"][0]
        # key_size = arguments["key_size"][0]

        file_path = await self.saveFile(request.files.get('file'))
        file_data = await self.readFileData(file_path)

        if(algorithm_type=="aes"):
            decrypted_message = await AES().decryptFileData(file_data, key)
        elif(algorithm_type=="des"):
            decrypted_message = await DES().decryptFileData(file_data, key)
        elif(algorithm_type=="des3"):
            key_size = arguments["key_size"][0]
            decrypted_message = await DES3().decryptFileData(file_data, key, int(key_size))
        elif(algorithm_type=="idea"):
            decrypted_message = await IDEA().decryptFileData(file_data, key)
        elif(algorithm_type=="blowfish"):
            decrypted_message = await Blowfish().decryptFileData(file_data, key)
        elif(algorithm_type=="twofish"):
            key_size = arguments["key_size"][0]
            decrypted_message = await Twofish().decryptFileData(file_data, key, int(key_size))

        return json({"success": True, 'decrypted_message': decrypted_message})

    async def saveFile(self, text_file):
        if not os.path.exists('./storage/temp'):
            os.makedirs('./storage/temp')

        file_parameters = {
            'body': text_file.body,
            'name': text_file.name,
            'type': text_file.type,
        }

        file_path = f"{'./storage/temp'}/{file_parameters['name']}"

        with open(file_path, 'wb') as f:
            f.write(file_parameters['body'])

        return(file_path)

    async def readFileData(self, file_path):
        data = ""

        with open(file_path, encoding="utf-8") as f:
            data = f.read()

        return data