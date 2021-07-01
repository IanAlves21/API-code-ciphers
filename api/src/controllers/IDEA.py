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
import numpy as np

class IDEA:
    async def encrypt(self, request: Request):
        arguments = request.json

        plain_text = arguments["message"]
        key = arguments["key"]

        encrypted_message = self.criptografiaIDEA(plain_text, key)

        return json({"success": True, 'encrypted_message': encrypted_message})

    async def decrypt(self, request: Request):
        arguments = request.json

        encrypted_message = arguments["message"]
        key = arguments["key"]

        decrypted_message = self.decriptografiaIDEA(encrypted_message, key)

        return json({"success": True, 'decrypted_message': decrypted_message})

    def encrypt_IDEA(self, plain_text, chave):
        lista_chaves = self.gerar_chaves(chave)

        # Converte texto string em binario
        plain_text_bin = ""
        temp = ""
        for i in plain_text: #Converte string ascii em Hex
            temp = temp + str(hex(ord(i)))[2:].zfill(2)
        for i in temp: # Transforma Hex em string de binario equivalente
            plain_text_bin = plain_text_bin + str(format(int(i, 16), '04b'))

        lista_iteracoes = [[plain_text_bin[i:i+16]] for i in range(0, len(plain_text_bin), 16)]

        for rodada in range(8):
            # Imagem explicativa das rodadas
            # https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm
            temp1 = self.mult_mod2_16(lista_iteracoes[0][rodada], lista_chaves[rodada*6])        # K1
            temp2 = self.add_mod2_16(lista_iteracoes[1][rodada], lista_chaves[(rodada*6) + 1])   # K2
            temp3 = self.add_mod2_16(lista_iteracoes[2][rodada], lista_chaves[(rodada*6) + 2])   # K3
            temp4 = self.mult_mod2_16(lista_iteracoes[3][rodada], lista_chaves[(rodada*6) + 3])  # K4

            temp5 = self.mult_mod2_16(self.funcXOR(temp1, temp3), lista_chaves[(rodada*6) + 4])   # K5

            temp6 = self.add_mod2_16(self.funcXOR(temp2, temp4), temp5)

            temp7 = self.mult_mod2_16(temp6, lista_chaves[(rodada*6) + 5])                   # K6

            temp8 = self.add_mod2_16(temp7, temp5)

            # Adiciona na lista pra ser usado na proxima rodada
            lista_iteracoes[0].append(self.funcXOR(temp1, temp7)) 
            lista_iteracoes[1].append(self.funcXOR(temp3, temp7))   # Inverte
            lista_iteracoes[2].append(self.funcXOR(temp2, temp8))   # Inverte
            lista_iteracoes[3].append(self.funcXOR(temp4, temp8))

        saida1 = (self.mult_mod2_16(lista_iteracoes[0][-1], lista_chaves[48]))
        saida2 = (self.add_mod2_16(lista_iteracoes[2][-1], lista_chaves[49]))
        saida3 = (self.add_mod2_16(lista_iteracoes[1][-1], lista_chaves[50]))
        saida4 = (self.mult_mod2_16(lista_iteracoes[3][-1], lista_chaves[51]))

        cifra = saida1 + saida2 + saida3 + saida4


        # Conversão de binário para hexadecimal
        output_bin = hex(int(cifra, 2)).upper()[2:].zfill(16)


        # # # Conversão hexadecimal para ascii
        # temp = ""
        # for i in range(8):
        #     temp = temp + chr(int(output_bin[i*2:(i+1)*2],16))

        return output_bin

    def decrypt_IDEA(self, cifra, chave):

        lista_chaves_temp = self.gerar_chaves(chave)
        lista_chaves = self.inverter_chave(lista_chaves_temp)

        # Converte texto string em binario
        plain_text_bin = ""
        # temp = ""
        # for i in cifra: #Converte string ascii em Hex
        #     temp = temp + str(hex(ord(i)))[2:].zfill(2)
        # for i in temp: # Transforma Hex em string de binario equivalente
        #     plain_text_bin = plain_text_bin + str(format(int(i, 16), '04b'))

        for i in cifra: # Transforma Hex em string de binario equivalente
            plain_text_bin = plain_text_bin + str(format(int(i, 16), '04b'))

        lista_iteracoes = [[plain_text_bin[i:i+16]] for i in range(0, len(plain_text_bin), 16)]

        for rodada in range(8):
            # Imagem explicativa das rodadas
            # https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm
            temp1 = self.mult_mod2_16(lista_iteracoes[0][rodada], lista_chaves[rodada*6])        # K1
            temp2 = self.add_mod2_16(lista_iteracoes[1][rodada], lista_chaves[(rodada*6) + 1])   # K2
            temp3 = self.add_mod2_16(lista_iteracoes[2][rodada], lista_chaves[(rodada*6) + 2])   # K3
            temp4 = self.mult_mod2_16(lista_iteracoes[3][rodada], lista_chaves[(rodada*6) + 3])  # K4

            temp5 = self.mult_mod2_16(self.funcXOR(temp1, temp3), lista_chaves[(rodada*6) + 4])   # K5

            temp6 = self.add_mod2_16(self.funcXOR(temp2, temp4), temp5)

            temp7 = self.mult_mod2_16(temp6, lista_chaves[(rodada*6) + 5])                   # K6

            temp8 = self.add_mod2_16(temp7, temp5)

            # Adiciona na lista pra ser usado na proxima rodada
            lista_iteracoes[0].append(self.funcXOR(temp1, temp7)) 
            lista_iteracoes[1].append(self.funcXOR(temp3, temp7))   # Inverte
            lista_iteracoes[2].append(self.funcXOR(temp2, temp8))   # Inverte
            lista_iteracoes[3].append(self.funcXOR(temp4, temp8))

        saida1 = (self.mult_mod2_16(lista_iteracoes[0][-1], lista_chaves[48]))
        saida2 = (self.add_mod2_16(lista_iteracoes[2][-1], lista_chaves[49]))
        saida3 = (self.add_mod2_16(lista_iteracoes[1][-1], lista_chaves[50]))
        saida4 = (self.mult_mod2_16(lista_iteracoes[3][-1], lista_chaves[51]))

        cifra = saida1 + saida2 + saida3 + saida4

        # Conversão de binário para hexadecimal
        output_bin = hex(int(cifra, 2)).upper()[2:].zfill(16)

        # Conversão hexadecimal para ascii
        temp = ""
        for i in range(8):
            temp = temp + chr(int(output_bin[i*2:(i+1)*2],16))

        return temp
        
    # Faz shift para esquerda de strings =================================================================================================================
    def shift_esquerda(self, word, shift):
        temp = word[shift:] + word[:shift]

        return temp

    #Entrada 2 strings binario, saida = string ===========================================================================================================
    def add_mod2_16(self, a, b):
        temp = int(a, 2) + int(b, 2)
        temp = temp % 2**16
        temp = format(temp, "016b")

        return temp

    #Entrada 2 strings binario, saida = string ===========================================================================================================
    def addinv_mod2_16(self, a):
        temp = (0x10000 - int(a,2)) % 2**16
        temp = format(temp, "016b")

        return temp

    #Entrada 2 strings binario, saida = string ============================================================================================================
    def mult_mod2_16(self, a, b):
        temp = int(a, 2) * int(b, 2)
        if(temp != 0):
            temp = (temp % 0x10001) % 2**16
        elif(int(a,2) != 0 or int(b,2) != 0):
            temp =  (1 - int(a,2) - int(b,2)) % 2**16
            
        temp = format(temp, "016b")

        return temp

    #Entrada 2 strings binario, saida = string ============================================================================================================
    # Encontrar o valor x, onde x*y mod (0x10001) = 1
    def multinv_mod2_16(self, b, m=(0x10001)):
        m0 = m
        a = int(b,2)
        y = 0
        x = 1
        if (m == 1):
            return 0
        while (a > 1):
            # q is quotient
            q = a // m
    
            t = m
            # m is remainder now, process same as Euclid's algo
            m = a % m
            a = t
            t = y
            # Update x and y
            y = x - q * y
            x = t
        # Make x positive
        if (x < 0):
            x = x + m0
        return format(x, "016b")

    #Faz XOR de 2 strings =================================================================================================================================
    def funcXOR (self, a, b):
        temp = int(a, 2) ^ int(b, 2)
        temp = format(temp % 2**16, "016b")
        
        return temp

    # Função de inverter as chaves para poderem ser usadas na decriptação =================================================================================
    def inverter_chave(self, lista_chaves):
        lista_reversa = [0]*52

        lista_reversa[48] = self.multinv_mod2_16(lista_chaves[0])
        lista_reversa[49] = self.addinv_mod2_16(lista_chaves[1])
        lista_reversa[50] = self.addinv_mod2_16(lista_chaves[2])
        lista_reversa[51] = self.multinv_mod2_16(lista_chaves[3])

        for r in reversed(range(1, 8)):
            lista_reversa[r*6 + 4] = lista_chaves[53 - r*6 - 7]                     # 4 ... 10 ...
            lista_reversa[r*6 + 5] = lista_chaves[53 - r*6 - 6]                     # 5 ... 11 ...
            lista_reversa[r*6 + 0] = self.multinv_mod2_16(lista_chaves[53 - r*6 - 5])    # 6 ... 12 ...
            lista_reversa[r*6 + 2] = self.addinv_mod2_16(lista_chaves[53 - r*6 - 4])     # 7 ... 13 ...
            lista_reversa[r*6 + 1] = self.addinv_mod2_16(lista_chaves[53 - r*6 - 3])     # 8 ... 14 ...
            lista_reversa[r*6 + 3] = self.multinv_mod2_16(lista_chaves[53 - r*6 - 2])    # 9 ... 15 ...

        lista_reversa[4] = lista_chaves[46]
        lista_reversa[5] = lista_chaves[47]
        lista_reversa[0] = self.multinv_mod2_16(lista_chaves[48])
        lista_reversa[1] = self.addinv_mod2_16(lista_chaves[49])
        lista_reversa[2] = self.addinv_mod2_16(lista_chaves[50])
        lista_reversa[3] = self.multinv_mod2_16(lista_chaves[51])

        return lista_reversa


    # Gera uma lista de chaves a partir do binario
    def gerar_chaves (self, chave_inicial): 

        # Dividir a chave em blocos de 8char/64bits
        bloco_chaves = [chave_inicial[i:i+2] for i in range(0, len(chave_inicial), 2)]
        bloco_chaves_bin = []

        # Transformar cada bloco em binario
        for bloco in bloco_chaves:
            chave_bin = ""
            temp = ""
            for i in bloco: #Converte string ascii em Hex
                temp = temp + str(hex(ord(i)))[2:].zfill(2)
            for i in temp: # Transforma Hex em string de binario equivalente
                chave_bin = chave_bin + str(format(int(i, 16), '04b'))
            bloco_chaves_bin.append(chave_bin)


        string_bin = ''.join(bloco_chaves_bin)
        temp_bloco = string_bin
        for i in range(6):
            temp_bloco = self.shift_esquerda(temp_bloco, 25)
            for j in range(len(temp_bloco)//16):
                bloco_chaves_bin.append(temp_bloco[j*16:(j+1)*16])

        bloco_chaves_bin = bloco_chaves_bin[:52] # Pop as últimas 4 chaves

        return bloco_chaves_bin


    # Função principal para criptografar texto e chave
    def criptografiaIDEA(self, plain_text, chave):
        # Divide a string em blocos de 8 char/ 64 bits
        bloco = [plain_text[i:i+8] for i in range(0, len(plain_text), 8)]
        bloco[-1] = bloco[-1].ljust(8)  #Adicionar preenchimento vazio no ultimo bloco, se precisar

        chave = chave.ljust(16, ".")[:16]

        # Aplica criptografia em todos os blocos, mesma chave
        bloco_criptografado = []
        for i in bloco:
            bloco_criptografado.append(self.encrypt_IDEA(i, chave))

        texto_cifrado = ''.join(bloco_criptografado)

        print("\n")
        print("Texto claro: " + plain_text)
        print("Chave usada: " + chave)
        print("Criptografado: " + texto_cifrado)

        return texto_cifrado

    # Função principal para descriptografar texto e chave
    def decriptografiaIDEA(self, cifra, chave): # Cifra = bloco de criptografados
        # Divide a string em blocos de 8
        bloco = [cifra[i:i+16] for i in range(0, len(cifra), 16)]

        chave = chave.ljust(16, ".")[:16]

        # Aplica decriptografia nos blocos
        bloco_decriptografado = []
        for i in bloco:
            bloco_decriptografado.append(self.decrypt_IDEA(i, chave))

        #Junta os blocos
        texto_decifrado = ''.join(bloco_decriptografado)

        print("\n")
        print("Texto Decriptografado: " + texto_decifrado)

        return texto_decifrado
