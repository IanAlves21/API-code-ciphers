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

class Twofish:
    async def encrypt(self, request: Request):
        arguments = request.json

        plain_text = arguments["message"]
        key_size = arguments["key_size"]
        key = arguments["key"]

        encrypted_message = self.criptografiaTwofish(plain_text, key, key_size)

        return json({"success": True, 'encrypted_message': encrypted_message})

    async def decrypt(self, request: Request):
        arguments = request.json

        encrypted_message = arguments["message"]
        key_size = arguments["key_size"]
        key = arguments["key"]

        decrypted_message = self.decriptografiaTwofish(encrypted_message, key, key_size)

        return json({"success": True, 'decrypted_message': decrypted_message})

        # Encriptação blowfish ================================================================================================================================
    def encrypt_Twofish(self, plain_text, chave, tamanho = 128):

        lista_chaves = self.gerar_chaves(chave, tamanho)
        chaves_s = self.gerar_chaves_S(chave)

        # # Converte o texto puro em binario
        plain_text_bin = ""
        temp = ""
        for i in plain_text: #Converte string ascii em Hex
            temp = temp + str(hex(ord(i)))[2:].zfill(2)
        # temp = "12345678945612345678952546158213"
        for i in temp: # Transforma Hex em string de binario equivalente
            plain_text_bin = plain_text_bin + str(format(int(i, 16), '04b'))

        # Dividir texto em 32 bits
        # lista[0] = 1º quartil 0 a 31
        # lista[1] = 2º quartil 32 a 63
        # lista[2] = 3º quartil 64 a 95
        # lista[3] = 4º quartil 96 a 127
        lista_iteracoes = [[plain_text_bin[i:i+32]] for i in range(0, len(plain_text_bin), 32)]

        #Input de chave inicial / Whitening
        for i in range(len(lista_iteracoes)):
            lista_iteracoes[i][-1] = self.whitening(lista_iteracoes[i][-1])
            lista_iteracoes[i][-1] = self.funcXOR(lista_iteracoes[i][-1], lista_chaves[i])

        # 16 Rodadas
        for rodada in range(16):
            # lista_iteracoes[x][rodada] = atual
            # lista_iteracoes[x][rodada + 1] = proximo

            # Função F
            temp_lista2, temp_lista3 = self.funcao_f(lista_iteracoes[0][rodada], lista_iteracoes[1][rodada], lista_chaves, rodada, chaves_s, False, tamanho)

            lista_iteracoes[2][rodada] = self.funcXOR(lista_iteracoes[2][rodada], temp_lista2)
            # Shift 1 para direita por definição
            lista_iteracoes[2][rodada] = self.shift_esquerda(lista_iteracoes[2][rodada], -1)

            # Rotacionar 1 pra esquerda por definição
            lista_iteracoes[3][rodada] = self.shift_esquerda(lista_iteracoes[3][rodada], 1)
            lista_iteracoes[3][rodada] = self.funcXOR(lista_iteracoes[3][rodada], temp_lista3)

            lista_iteracoes[0].append(lista_iteracoes[2][rodada])
            lista_iteracoes[1].append(lista_iteracoes[3][rodada])
            lista_iteracoes[2].append(lista_iteracoes[0][rodada])
            lista_iteracoes[3].append(lista_iteracoes[1][rodada])


        y0 = [lista_iteracoes[2][-1], lista_iteracoes[3][-1], lista_iteracoes[0][-1], lista_iteracoes[1][-1]]
        #Input de chave final
        for i in range(4):
            # Aplica as ultimas chaves
            y0[i] = hex(int(self.funcXOR(y0[i], lista_chaves[i+4]), 2)).upper()[2:].zfill(8)

        # Inverte a cifra 2 a 2 pra cada conjunto de 8 hexa
        # Formato Endiano
        for i in range(4):
            temp = ""
            ans=[y0[i][j:j+2] for j in range(0,len(y0[i]),2)]
            ans=ans[::-1]
            y0[i] = ''.join(ans)
        cifra = ''.join(y0)

        # #Conversão hexadecimal para ascii
        # temp = ""
        # for i in range(16):
        #     temp = temp + chr(int(cifra[i*2:(i+1)*2],16))

        return cifra


    # Decryptação, É a mesma coisa que a encriptação, só que as chaves são aplicadas ao contrário =========================================================
    # Grande ajuda: https://github.com/d4rkvaibhav/twofish_python/blob/main/cipher_twofish.py
    def decrypt_Twofish(self, crypted_text, chave, tamanho = 128):

        lista_chaves = self.gerar_chaves(chave, tamanho)
        chaves_s = self.gerar_chaves_S(chave)

        # Converte o texto puro em binario
        plain_text_bin = ""
        # temp = ""
        # for i in crypted_text: #Converte string ascii em Hex
        #     temp = temp + str(hex(ord(i)))[2:].zfill(2)

        #Reverter formato endiano
        text_hex = [crypted_text[i:i+8] for i in range(0, len(crypted_text), 8)]
        for i in range(4):
            hex_temp = [text_hex[i][j:j+2] for j in range(0, len(text_hex[i]), 2)]
            text_hex[i] = ''.join(hex_temp[::-1])

        text_hex = ''.join(text_hex)

        for i in text_hex: # Transforma Hex em string de binario equivalente
            plain_text_bin = plain_text_bin + str(format(int(i, 16), '04b'))

        # Dividir texto em 32 bits
        # lista[0] = 1º quartil 0 a 31
        # lista[1] = 2º quartil 32 a 63
        # lista[2] = 3º quartil 64 a 95
        # lista[3] = 4º quartil 96 a 127
        lista_temp = [plain_text_bin[i:i+32] for i in range(0, len(plain_text_bin), 32)]
        lista_iteracoes = [[], [], [], []]

        #Input da chave final, para decriptação
        for i in range(len(lista_temp)):
            lista_temp[i] = self.funcXOR(lista_temp[i], lista_chaves[i+4])

        # Reversão inicial para decriptação
        lista_iteracoes[0].append(lista_temp[2])
        lista_iteracoes[1].append(lista_temp[3])
        lista_iteracoes[2].append(lista_temp[0])
        lista_iteracoes[3].append(lista_temp[1])

        # 16 Rodadas
        for rodada in range(16):
            # lista_iteracoes[x][rodada] = atual
            # lista_iteracoes[x][rodada + 1] = proximo
            
            lista_iteracoes[0].append(lista_iteracoes[2][rodada])
            lista_iteracoes[1].append(lista_iteracoes[3][rodada])
            lista_iteracoes[2].append(lista_iteracoes[0][rodada])
            lista_iteracoes[3].append(lista_iteracoes[1][rodada])

            rodada_decrypt = rodada + 1
            # Função F
            temp_lista2, temp_lista3 = self.funcao_f(lista_iteracoes[0][rodada_decrypt], lista_iteracoes[1][rodada_decrypt], lista_chaves, rodada, chaves_s, True, tamanho)
            
            # Shift 1 para esquerda na decriptacao
            lista_iteracoes[2][rodada_decrypt] = self.shift_esquerda(lista_iteracoes[2][rodada_decrypt], 1)
            lista_iteracoes[2][rodada_decrypt] = self.funcXOR(lista_iteracoes[2][rodada_decrypt], temp_lista2)
            
            lista_iteracoes[3][rodada_decrypt] = self.funcXOR(lista_iteracoes[3][rodada_decrypt], temp_lista3)
            # Rotacionar 1 pra direita na decriptação
            lista_iteracoes[3][rodada_decrypt] = self.shift_esquerda(lista_iteracoes[3][rodada_decrypt], -1)


        y0 = [lista_iteracoes[0][-1], lista_iteracoes[1][-1], lista_iteracoes[2][-1], lista_iteracoes[3][-1]]

        #Input de chave inicial, para decriptação
        for i in range(4):
            # Aplica as ultimas chaves
            y0[i] = hex(int(self.funcXOR(y0[i], lista_chaves[i]), 2))[2:].zfill(8)

        decifra_temp = ''.join(y0)

        # Output deve ser desmisturado com o formato Endian
        decifra = [decifra_temp[i:i+8] for i in range(0, len(decifra_temp), 8)]
        for j in range(4):
            text_hex = [decifra[j][i:i+2] for i in range(0, len(decifra[j]), 2)]
            decifra[j] = ''.join(text_hex[::-1])
        decifra = ''.join(decifra)

        #Conversão hexadecimal para ascii
        temp = ""
        for i in range(16):
            temp = temp + chr(int(decifra[i*2:(i+1)*2],16))

        return temp

    # Aplica as chaves iniciais
    def whitening (self, entrada):
        temp = entrada
        #Formato endiano
        text_hex = [temp[i:i+8] for i in range(0, len(temp), 8)]
        temp = ''.join(text_hex[::-1])

        return temp


    # Faz permutacao passando pela matriz q0 ==============================================================================================================
    # entrada = 8 bits string
    # saida = 8 bits string
    def permuta_q0 (self, entrada):
        ror4 = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]
        ashx = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7]
        q0 = [  [0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4],
                [0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD],
                [0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1],
                [0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA]]
        a0, b0 = entrada[0:4], entrada[4:8]
        
        a1 = self.funcXOR(a0, b0)
        b1 = format(ror4[int(b0, 2)] ^ ashx[int(a0, 2)], "04b")

        a2 = q0[0][int(a1, 2)] # Passa pela tabela
        b2 = q0[1][int(b1, 2)]
        a2 = format(a2, '04b') # Transforma em binario
        b2 = format(b2, '04b')
        
        a3 = self.funcXOR(a2, b2)
        b3 = format(ror4[int(b2, 2)] ^ ashx[int(a2, 2)], "04b")

        a4 = q0[2][int(a3, 2)] # Passa pela tabela
        b4 = q0[3][int(b3, 2)]
        a4 = format(a4, '04b') # Transforma em binario
        b4 = format(b4, '04b')

        return b4 + a4

    # Faz permutacao passando pela matriz q1 ==============================================================================================================
    # entrada = 8 bits string
    # saida = 8 bits string
    def permuta_q1 (self, entrada):
        ror4 = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]
        ashx = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7]
        q1 = [  [ 0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5],
                [ 0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8],
                [ 0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF],
                [ 0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA]]
        a0, b0 = entrada[0:4], entrada[4:8]
        
        a1 = self.funcXOR(a0, b0)
        b1 = format(ror4[int(b0, 2)] ^ ashx[int(a0, 2)], "04b")

        a2 = q1[0][int(a1, 2)] # Passa pela tabela
        b2 = q1[1][int(b1, 2)]
        a2 = format(a2, '04b') # Transforma em binario
        b2 = format(b2, '04b')
        
        a3 = self.funcXOR(a2, b2)
        b3 = format(ror4[int(b2, 2)] ^ ashx[int(a2, 2)], "04b")

        a4 = q1[2][int(a3, 2)] # Passa pela tabela
        b4 = q1[3][int(b3, 2)]
        a4 = format(a4, '04b') # Transforma em binario
        b4 = format(b4, '04b')

        return b4 + a4

    # Faz uma multiplicação de matriz com a matriz mds ====================================================================================================
    # Entrada = Inteiro 32 bits
    # Saida = String 32 bits
    def MDS(self, a):
        matriz_mds = [  [0x01, 0xEF, 0x5B, 0x5B],
                        [0x5B, 0xEF, 0xEF, 0x01],
                        [0xEF, 0x5B, 0x01, 0xEF],
                        [0xEF, 0x01, 0xEF, 0x5B]]
        res = [0, 0, 0, 0]
        temp_xor = 0
        for i in range(4):
            for k in range(4):
                temp_xor = temp_xor ^ self.byte_mul(matriz_mds[i][k], a[k], "M")

            res[i] = temp_xor
            temp_xor = 0
        # for i in range(4):
        #     res[i] = format(res[i], "08b")

        return res
        # return ''.join(res)

    # Multiplicação de Galois Field GF(2^8) ===============================================================================================================
    # Basicamente é uma multiplicação de polinomios que estão representados binariametne
    # ENTRADA = 2 HEX
    # SAIDA = HEX/INT
    def byte_mul(self, a, b, modulus):
        p = 0
        for c in range(8):
            if b & 1:
                p ^= a
            a <<= 1
            if a & 0x100:
                if modulus == "S":
                    # a ^= 0x11b
                    a ^= 0x14d
                else:            
                    a ^= 0x169
            b >>= 1
        return p

    # Faz a soma binária de 2 strings =====================================================================================================================
    def binSum (self, a, b):
        integer = int(a, 2) + int(b, 2)
        bin = "{0:032b}".format(integer)[-32:] # Pega apenas os ultimos 32 numeros
        return bin


    #Faz XOR de 2 strings =================================================================================================================================
    def funcXOR (self, a, b):
        # Faz XOR de 2 strings
        temp = ""
        for i in list(zip(a, b)):
            temp = temp + str(int(i[0]) ^ int(i[1]))
            # print(i[0], i[1])
        
        return temp

    # Faz shift para esquerda de strings =================================================================================================================
    def shift_esquerda(self, word, shift):
        temp = word[shift:] + word[:shift]

        return temp


    # Entrada = string 32 bits
    # Saida =  string 32 bits
    def funcao_f(self, texto_quartil0, texto_quartil1, lista_chaves, rodada, chaves_s, inverso = False, tamanho = 128):
        # Shift inicial do quartil 1 para esquerda, 8 bits
        texto_quartil1_temp = self.shift_esquerda(texto_quartil1, 8)

        # Dividir em 4 partes
        temp0 = [texto_quartil0[i:i+8] for i in range(0, len(texto_quartil0), 8)]
        temp1 = [texto_quartil1_temp[i:i+8] for i in range(0, len(texto_quartil1_temp), 8)]
        # print(int(temp0[0], 2), int(temp0[1], 2), int(temp0[2], 2) ,int(temp0[3], 2))
        temp0_concat = ''.join(temp0[::-1])
        temp1_concat = ''.join(temp1[::-1])
        # print(temp0)

        if(tamanho > 192): # 256 bits de chave
            for i in range(4):          # Primeira rodada, i = caixas
                if(i == 1 or i == 2): # 1 e 4
                    temp0[i] = self.permuta_q0(temp0_concat[i*8: (i+1)*8])   #Chave par
                    temp1[i] = self.permuta_q0(temp1_concat[i*8: (i+1)*8])   #Chave impar
                else:
                    temp0[i] = self.permuta_q1(temp0_concat[i*8: (i+1)*8])
                    temp1[i] = self.permuta_q1(temp1_concat[i*8: (i+1)*8])

            # Aplicar chaves
            temp0_concat = self.funcXOR(''.join(temp0), chaves_s[3])  # S3
            temp1_concat = self.funcXOR(''.join(temp1), chaves_s[3])  # S3
            # print("!")

        if(tamanho > 128): # 192 bits de chave
            for i in range(4):          # Primeira rodada, i = caixas
                if(i > 1 == 0): # 2 e 3
                    temp0[i] = self.permuta_q0(temp0_concat[i*8: (i+1)*8])   #Chave par
                    temp1[i] = self.permuta_q0(temp1_concat[i*8: (i+1)*8])   #Chave impar
                else:
                    temp0[i] = self.permuta_q1(temp0_concat[i*8: (i+1)*8])
                    temp1[i] = self.permuta_q1(temp1_concat[i*8: (i+1)*8])


            # Aplicar chaves
            temp0_concat = self.funcXOR(''.join(temp0), chaves_s[2]) # S2
            temp1_concat = self.funcXOR(''.join(temp1), chaves_s[2]) # S2
            # print("!")
        
        # Caixas S
        # Caixas q0 e q1
        for i in range(4):          # Primeira rodada, i = caixas
            if(i % 2 == 0): # 0 e 2
                temp0[i] = self.permuta_q0(temp0_concat[i*8: (i+1)*8])    #Chave par
                temp1[i] = self.permuta_q0(temp1_concat[i*8: (i+1)*8])    #Chave par
            else:
                temp0[i] = self.permuta_q1(temp0_concat[i*8: (i+1)*8])
                temp1[i] = self.permuta_q1(temp1_concat[i*8: (i+1)*8])

        # Aplicar chaves
        temp0_concat = self.funcXOR(''.join(temp0), chaves_s[0])   # S1
        temp1_concat = self.funcXOR(''.join(temp1), chaves_s[0])   # S1

        # Caixas q0 e q1, rodada 2
        for i in range(4):
            if(i < 2):      # 0 e 1
                temp0[i] = self.permuta_q0(temp0_concat[i*8: (i+1)*8])
                temp1[i] = self.permuta_q0(temp1_concat[i*8: (i+1)*8])
            else:
                temp0[i] = self.permuta_q1(temp0_concat[i*8: (i+1)*8])
                temp1[i] = self.permuta_q1(temp1_concat[i*8: (i+1)*8])

        # Aplicar chaves
        temp0_concat = self.funcXOR(''.join(temp0), chaves_s[1])   # S0
        temp1_concat = self.funcXOR(''.join(temp1), chaves_s[1])   # S0

        # Caixas q0 e q1, rodada 3
        for i in range(4):
            if (i % 2 != 0): # 1 e 3
                temp0[i] = self.permuta_q0(temp0_concat[i*8: (i+1)*8])
                temp1[i] = self.permuta_q0(temp1_concat[i*8: (i+1)*8])
            else:
                temp0[i] = self.permuta_q1(temp0_concat[i*8: (i+1)*8])
                temp1[i] = self.permuta_q1(temp1_concat[i*8: (i+1)*8])

        temp0_concat = ''.join(temp0)
        temp1_concat = ''.join(temp1)

        temp0 = [int(temp0_concat[i:i+8], 2) for i in range(0, len(temp0_concat), 8)]
        temp1 = [int(temp1_concat[i:i+8], 2) for i in range(0, len(temp1_concat), 8)]

        # Caixa self.MDS
        mds_0 = self.MDS(temp0)
        mds_1 = self.MDS(temp1) 

        mds_0 = mds_0[::-1]
        mds_1 = mds_1[::-1]
        # mds = 32 bits
        for i in range(4):
            mds_0[i] = format(mds_0[i], "08b")
            mds_1[i] = format(mds_1[i], "08b")
        mds_0 = ''.join(mds_0)
        mds_1 = ''.join(mds_1)

        # Caixa PHT
        saida0 = self.binSum(mds_0, mds_1)  
        saida1 = self.binSum(saida0, mds_1)

        # Misturar com a chave da rodada
        # Rodada de 0 a 15
        if(inverso == False): #Criptografia
            saida0 = self.binSum(saida0, lista_chaves[2* rodada + 8])
            saida1 = self.binSum(saida1, lista_chaves[2* rodada + 9])
        else:
            saida0 = self.binSum(saida0, lista_chaves[2*(15 - rodada) + 8])
            saida1 = self.binSum(saida1, lista_chaves[2*(15 - rodada) + 9])

        return saida0, saida1


    # Gera uma lista de chaves a partir do binario ========================================================================================================
    def gerar_chaves (self, chave, tamanho = 128): 
        
        chave_hex = ""
        for i in chave:  # Converte cada item ascii em Hex
            chave_hex = chave_hex + str(hex(ord(i)))[2:].zfill(2)

        # chave_hex = "12345678945612345678952546158213"
        # chave_hex = "0123456789ABCDEFFEDCBA9876543210"
        # chave_hex = "0123456789ABCDEFFEDCBA98765432100011223344556677"
        # chave_hex = "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF"

        # # Gera as chaves m pra poder gerar as outras chaves
        chave_m_par = []
        chave_m_impar = []

        for i in range(tamanho//32):
            text_bin = ""
            for j in chave_hex[i*8:(i+1)*8]:
                text_bin = text_bin + format(int(j, 16), "04b")
            if(i % 2 == 0):
                chave_m_par.append(text_bin)
            else:
                chave_m_impar.append(text_bin)

        # Função H, 20 iterações pra produzir 40 chaves
        lista_chaves = []
        temp0 = ["", "", "", ""]
        temp1 = ["", "", "", ""]
        for rodada in range(20):
        # Caixas S
        # Caixas q0 e q1
            for i in range(4):
                temp0[i] = format(2 * rodada, "08b")
                temp1[i] = format((2 * rodada) + 1, "08b")
            temp0_concat = ''.join(temp0)
            temp1_concat = ''.join(temp1)
            
            if(tamanho > 192): # 256 bits de chave
                for i in range(4):          # Primeira rodada, i = caixas
                    if(i == 1 or i == 2): # 2 e 3
                        temp0[i] = self.permuta_q0(temp0_concat[i*8: (i+1)*8])   #Chave par
                        temp1[i] = self.permuta_q0(temp1_concat[i*8: (i+1)*8])   #Chave impar
                    else:
                        temp0[i] = self.permuta_q1(temp0_concat[i*8: (i+1)*8])
                        temp1[i] = self.permuta_q1(temp1_concat[i*8: (i+1)*8])

                # Aplicar chaves
                temp0_concat = self.funcXOR(''.join(temp0), chave_m_par[3])   # M6
                temp1_concat = self.funcXOR(''.join(temp1), chave_m_impar[3]) # M7

            if(tamanho > 128): # 192 bits de chave
                for i in range(4):          # Primeira rodada, i = caixas
                    if(i > 1 == 0): # 2 e 3
                        temp0[i] = self.permuta_q0(temp0_concat[i*8: (i+1)*8])   #Chave par
                        temp1[i] = self.permuta_q0(temp1_concat[i*8: (i+1)*8])   #Chave impar
                    else:
                        temp0[i] = self.permuta_q1(temp0_concat[i*8: (i+1)*8])
                        temp1[i] = self.permuta_q1(temp1_concat[i*8: (i+1)*8])

                # Aplicar chaves
                temp0_concat = self.funcXOR(''.join(temp0), chave_m_par[2])   # M4
                temp1_concat = self.funcXOR(''.join(temp1), chave_m_impar[2]) # M5
                # print("!")

            for i in range(4):  # Primeira rodada, i = caixas
                if(i % 2 == 0): # 0 e 2
                    temp0[i] = self.permuta_q0(temp0_concat[i*8: (i+1)*8])   #Chave par
                    temp1[i] = self.permuta_q0(temp1_concat[i*8: (i+1)*8])   #Chave impar
                else:
                    temp0[i] = self.permuta_q1(temp0_concat[i*8: (i+1)*8])
                    temp1[i] = self.permuta_q1(temp1_concat[i*8: (i+1)*8])

            # Aplicar chaves
            temp0_concat = self.funcXOR(''.join(temp0), chave_m_par[1])   # M2
            temp1_concat = self.funcXOR(''.join(temp1), chave_m_impar[1]) # M3

            # # Caixas q0 e q1, rodada 2
            for i in range(4):
                if(i < 2):
                    temp0[i] = self.permuta_q0(temp0_concat[i*8: (i+1)*8])
                    temp1[i] = self.permuta_q0(temp1_concat[i*8: (i+1)*8])
                else:
                    temp0[i] = self.permuta_q1(temp0_concat[i*8: (i+1)*8])
                    temp1[i] = self.permuta_q1(temp1_concat[i*8: (i+1)*8])

            # Aplicar chaves
            temp0_concat = self.funcXOR(''.join(temp0), chave_m_par[0])   # M0
            temp1_concat = self.funcXOR(''.join(temp1), chave_m_impar[0]) # M1

            # Caixas q0 e q1, rodada 3
            for i in range(4):
                if (i % 2 != 0): # 1 e 3
                    temp0[i] = self.permuta_q0(temp0_concat[i*8: (i+1)*8])
                    temp1[i] = self.permuta_q0(temp1_concat[i*8: (i+1)*8])
                else:
                    temp0[i] = self.permuta_q1(temp0_concat[i*8: (i+1)*8])
                    temp1[i] = self.permuta_q1(temp1_concat[i*8: (i+1)*8])

            temp0_concat = ''.join(temp0)
            temp1_concat = ''.join(temp1)

            # Dividir 32 bits em 8 bits e transformar em inteiro
            temp0 = [int(temp0_concat[i:i+8], 2) for i in range(0, len(temp0_concat), 8)]
            temp1 = [int(temp1_concat[i:i+8], 2) for i in range(0, len(temp1_concat), 8)]

            # Caixa self.MDS
            mds_0 = self.MDS(temp0)
            mds_1 = self.MDS(temp1)

            for i in range(4):
                mds_0[i] = format(mds_0[i], "08b")
                mds_1[i] = format(mds_1[i], "08b")

            mds_0 = mds_0[::-1]
            mds_1 = mds_1[::-1]
            mds_0 = ''.join(mds_0)
            mds_1 = ''.join(mds_1)

            mds_1 = self.shift_esquerda(mds_1, 8) # Shift esquerda 8 por definicao

            # Caixa PHT
            saida0 = self.binSum(mds_0, mds_1)  
            saida1 = self.shift_esquerda(self.binSum(saida0, mds_1), 9)

            # Adicionar a lista de chaves
            lista_chaves.append(saida0)
            lista_chaves.append(saida1)

        # lista_hex = [0] * 40
        # for i in range(len(lista_chaves)):
        #     lista_hex[i] = str(hex(int(lista_chaves[i], 2))).upper()[2:].zfill(8)
        # print(lista_hex)

        return lista_chaves

    def gerar_chaves_S(self, chave):
        # RS = [4][8]
        RS =[   [ 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
                [ 0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
                [ 0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
                [ 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]]

        chave_hex = ""
        for i in chave:  # Converte cada item ascii em Hex
            chave_hex = chave_hex + str(hex(ord(i)))[2:].zfill(2)

        # chave_hex = "12345678945612345678952546158213"
        # chave_hex = "0123456789ABCDEFFEDCBA9876543210"
        # chave_hex = "0123456789ABCDEFFEDCBA98765432100011223344556677"
        # chave_hex = "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF"

        temp_chave_S = []
        for i in range(len(chave_hex) // 2):
            temp_chave_S.append(int(chave_hex[i*2:(i+1)*2], 16))
        
        # Geração de chaves S
        # Multiplicação de matrizes da chave original com o RS
        chave_s = []
        temp = 0x00
        for k in range(len(chave_hex)//16):
            chave_s.append([])
            for i in range(4):
                for j in range(8):
                        temp = temp ^ self.byte_mul(RS[i][j], temp_chave_S[j + k*8], "S")

                chave_s[k].append(temp)
                temp = 0x00

        for i in range(len(chave_hex)//16):
            for j in range(4):
                chave_s[i][j] = format(chave_s[i][j], "08b")
        
            chave_s[i] = ''.join(chave_s[i])

        # print(chave_s)

        return chave_s

        

    # Função principal para criptografar texto e chave ====================================================================================================
    def criptografiaTwofish(self, plain_text, chave, tamanho = 128):
        # Divide a string em blocos de 8 ascii = 64 bits
        bloco = [plain_text[i:i+16] for i in range(0, len(plain_text), 16)]
        bloco[-1] = bloco[-1].ljust(16)  #Adicionar preenchimento vazio no ultimo bloco, se precisar

        chave = chave.ljust(tamanho//8, ".")[:tamanho//8]

        # Aplica criptografia em todos os blocos, mesma chave
        bloco_criptografado = []
        for i in bloco:
            bloco_criptografado.append(self.encrypt_Twofish(i, chave, tamanho))

        print("\n")
        print("Texto claro: " + plain_text)
        print("Chave usada: " + chave[:tamanho//8]) # N de chr ASCII usados
        criptografado = ''.join(bloco_criptografado)
        print("Criptografado: ")
        print(criptografado)

        return criptografado

    # Função principal para descriptografar texto e chave =================================================================================================
    def decriptografiaTwofish(self, cifra, chave, tamanho = 128): # Cifra = bloco de criptografados

        # Divide a string em blocos de 128bits
        bloco = [cifra[i:i+32] for i in range(0, len(cifra), 32)]
        
        # Garante que a chave tenha o numero minimo de caracteres ascii de acordo com o tamanho
        chave = chave.ljust(tamanho//8, ".")[:tamanho//8]

        # Pega os blocos criptografados e decriptografa cada parte
        bloco_decriptografado = []
        for i in bloco:
            bloco_decriptografado.append(self.decrypt_Twofish(i, chave, tamanho))

        print("\n")
        descriptografado = ''.join(bloco_decriptografado)
        print("Texto Decriptografado: " + descriptografado)

        return descriptografado
