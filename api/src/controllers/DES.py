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

class DES:
    async def encrypt(self, request: Request):
        arguments = request.json

        plain_text = arguments["message"]
        key = arguments["key"]

        encrypted_message = self.criptografiaDES(plain_text, key)

        return json({"success": True, 'encrypted_message': encrypted_message})

    async def decrypt(self, request: Request):
        arguments = request.json
        
        encrypted_message = arguments["message"]
        key = arguments["key"]

        decrypted_message = self.decriptografiaDES(encrypted_message, key)

        return json({"success": True, 'decrypted_message': decrypted_message})

    async def encryptFileData(self, plain_text, key):
        encrypted_message = self.criptografiaDES(plain_text, key)

        return encrypted_message

    async def decryptFileData(self, encrypted_message, key):
        decrypted_message = self.decriptografiaDES(encrypted_message, key)

        return decrypted_message

    def encrypt_DES(self, plain_text, chave):

        plain_text_bin = ""
        
        temp = ""

        for i in plain_text: #Converte string ascii em Hex
            temp = temp + str(hex(ord(i)))[2:].zfill(2)

        for i in temp: # Transforma Hex em string de binario equivalente
            plain_text_bin = plain_text_bin + str(format(int(i, 16), '04b'))


        # Gera uma lista de chaves que será usado na encryptação
        lista_chaves = self.gerar_chaves(chave)

        # Faz a permutacao inicial
        texto_permutado = self.IP(plain_text_bin)

        # Divide o texto em 2 partes
        texto_esquerda = texto_permutado[:int(len(texto_permutado)/2)]
        texto_direita = texto_permutado[int(len(texto_permutado)/2):]

        # Texto é colocado como o primeiro da lista de iteracoes
        lista_iteracoes = [[texto_esquerda], [texto_direita]]


        # 16 iteracoes de encriptacao
        for iteracao in range(16):
            # lista_iteracoes[0][iteracao] é o L anterior
            # lista_iteracoes[1][iteracao] é o R anterior

            #Novo texto_esquerda é o texto_direita antigo
            lista_iteracoes[0].append(lista_iteracoes[1][iteracao])

            #Novo texto_direita é o (texto_esquerda_antigo) XOR (Funcao Feistel do texto_direita_antigo)
            text_R_temp = self.funcao_Feistel(lista_iteracoes[1][iteracao], lista_chaves[iteracao])
            texto_direita_novo = int(lista_iteracoes[0][iteracao], base = 2) ^ int(text_R_temp, base = 2)
            lista_iteracoes[1].append('{:032b}'.format(texto_direita_novo))

        # Permutação inversa para finalizar
        output = self.IIP(lista_iteracoes[1][-1] + lista_iteracoes[0][-1])

        # Conversão de binário para hexadecimal
        output_bin = str(hex(int(output, 2))).upper()[2:].zfill(16)

        # #Conversão hexadecimal para ascii
        # temp = ""
        # for i in range(8):
        #     temp = temp + chr(int(output_bin[i*2:(i+1)*2],16))

        return output_bin


    # Decryptação, É a mesma coisa que a encriptação, só que as chaves são aplicadas ao contrário
    def decrypt_DES(self, crypted_text, chave):

        crypted_text_bin = ""

        # temp = ""
        # for i in crypted_text: #Converte string ascii em Hex
        #     temp = temp + str(hex(ord(i)))[2:].zfill(2)

        # for i in temp: # Transforma Hex em string de binario equivalente
        #     crypted_text_bin = crypted_text_bin + str(format(int(i, 16), '04b'))

        for i in crypted_text: # Transforma Hex em string de binario equivalente
            crypted_text_bin = crypted_text_bin + str(format(int(i, 16), '04b'))

        # Gera uma lista de chaves que será usado na encryptação
        lista_chaves = self.gerar_chaves(chave)

        # Faz a permutacao inicial
        texto_permutado = self.IP(crypted_text_bin)

        # Divide o texto em 2 partes
        texto_esquerda = texto_permutado[:int(len(texto_permutado)/2)]
        texto_direita = texto_permutado[int(len(texto_permutado)/2):]

        # Texto é colocado como o primeiro da lista de iteracoes
        lista_iteracoes = [[texto_esquerda], [texto_direita]]


        # 16 iteracoes de encriptacao
        for iteracao in range(16):
            # lista_iteracoes[0][iteracao] é o L anterior
            # lista_iteracoes[1][iteracao] é o R anterior

            #Novo texto_esquerda é o texto_direita antigo
            lista_iteracoes[0].append(lista_iteracoes[1][iteracao])

            #Novo texto_direita é o (texto_esquerda_antigo) XOR (Funcao Feistel do texto_direita_antigo)
            text_R_temp = self.funcao_Feistel(lista_iteracoes[1][iteracao], lista_chaves[15 - iteracao])
            texto_direita_novo = int(lista_iteracoes[0][iteracao], base = 2) ^ int(text_R_temp, base = 2)
            lista_iteracoes[1].append('{:032b}'.format(texto_direita_novo))

        # Permutação inversa para finalizar
        output = self.IIP(lista_iteracoes[1][-1] + lista_iteracoes[0][-1])

        # Conversão de binário para hexadecimal
        output_bin = str(hex(int(output, 2))).upper()[2:].zfill(16)

        #Conversão hexadecimal para ascii
        temp = ""
        for i in range(8):
            temp = temp + chr(int(output_bin[i*2:(i+1)*2],16))

        return temp

    def IP(self, chave): # Initial Permutation
        tabela = [  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
        temp = []
        for i in tabela:
            temp.append(chave[i-1])

        return ''.join(temp)

    def IIP(self, chave): # Inverse Initial Permutation
        tabela = [  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
                    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
                    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
                    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
        temp = []
        for i in tabela:
            temp.append(chave[i-1])

        return ''.join(temp)

    # Aplica a funcao de Feistel para encriptacao
    def funcao_Feistel(self, texto, chave):
        expansao_e = [  32, 1,  2,  3,  4,  5, 4,  5,  6,  7,  8,  9, 
                        8,  9,  10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 
                        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 
                        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 ]

        permutacao_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

        # [8][4][16]
        # Ex: [0][1][0] == 0
        funcoes_S = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],   # S1
                    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

                    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],    # S2
                    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

                    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],    # S3
                    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

                    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],    # S4
                    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

                    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],    # S5
                    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

                    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],    # S6
                    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

                    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],    # S7
                    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

                    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],    # S8
                    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
        
        # Passo 1 = texto está em 32 bits e chave está em 48, precisa expandir o texto.
        expanded_temp = []
        for i in expansao_e:
            expanded_temp.append(texto[i-1])
        expanded_text = ''.join(expanded_temp)

        # Passo 2 = XOR do texto expandido com a chave=============================================================

        xor_temp = int(expanded_text, base=2) ^ int(chave, base=2)
        texto_chave = "{:048b}".format(xor_temp)

        # Passo 3 = Dividir o texto_chave em 8 partes de 6 bits ===================================================

        lista_texto_chave = []
        for i in range(8):
            lista_texto_chave.append(texto_chave[(i*6): ((i+1)*6)])

        # Passo 4 = Pegar cada parte de 6 bits e colocar nas funcoes S ============================================
        # Primeiro e ultimo bit: define a linha
        # 4 bits do meio: define a coluna
        # Resultado em binario é a saída

        lista_funcao_s = []

        for i in range(len(funcoes_S)):
            linha_temp = int(lista_texto_chave[i][0] + lista_texto_chave[i][-1], base = 2)
            coluna_temp = int(lista_texto_chave[i][1:-1], base = 2)
            bin_temp = funcoes_S[i][linha_temp][coluna_temp]
            lista_funcao_s.append("{:04b}".format(bin_temp))

        output_s_box = ''.join(lista_funcao_s)

        # Passo 5 = Passar pela permutacao P ======================================================================

        perm_p = []

        for i in permutacao_P:
            perm_p.append(output_s_box[i-1])
        saida = ''.join(perm_p)

        return saida
        
        

    def PC_1(self, chave): # Escolha permutada 1
        tabela = [  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
                    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
        temp = []
        for i in tabela:
            temp.append(chave[i-1])

        return ''.join(temp)

    def PC_2(self, chave): # Escolha permutada 2
        tabela = [  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
                    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
                    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
        temp = []
        for i in tabela:
            temp.append(chave[i-1])

        return ''.join(temp)

    # Escalonamento deslocamento para esquerda, geracao de chaves
    # Gera uma lista de chaves a partir do binario
    def gerar_chaves(self, chave_inicial): 
        tabela = [  1, 1, 2, 2, 2, 2, 2, 2,
                    1, 2, 2, 2, 2, 2, 2, 1]
        # Chave esquerda [0][x], chave direita [1][x]
        lista_chaves_temp = [[], []]
        lista_chaves = []

        chave = ""

        temp = ""

        for i in chave_inicial: #Converte string ascii em Hex
            temp = temp + str(hex(ord(i)))[2:].zfill(2)

        for i in temp: # Transforma Hex em string de binario equivalente
            chave = chave + str(format(int(i, 16), '04b'))


        # Aplica a permuta 1
        chave_permuta_1 = self.PC_1(chave)

        # Divide em esquerda e direita    
        chave_esq = chave_permuta_1[:int(len(chave_permuta_1)/2)]
        chave_dir = chave_permuta_1[int(len(chave_permuta_1)/2):]

        #Coloca a chave na lista para que sejam manipuladas
        lista_chaves_temp[0].append(chave_esq)
        lista_chaves_temp[1].append(chave_dir)

        #  Pega a chave direita e esqueda e vai dando shift de acordo com a tabela
        for i in range(len(tabela)):
            temp = tabela[i]
            lista_chaves_temp[0].append(lista_chaves_temp[0][i][temp:] + lista_chaves_temp[0][i][:temp])
            lista_chaves_temp[1].append(lista_chaves_temp[1][i][temp:] + lista_chaves_temp[1][i][:temp])

        # Remove a chave original
        lista_chaves_temp[0] = lista_chaves_temp[0][1:]
        lista_chaves_temp[1] = lista_chaves_temp[1][1:]

        # Concatena as chaves e passa pela permuta 2
        for i in range(len(lista_chaves_temp[0])):
            chave_temp = lista_chaves_temp[0][i] + lista_chaves_temp[1][i]
            lista_chaves.append(self.PC_2(chave_temp))

        return lista_chaves


    # Função principal para criptografar texto e chave
    def criptografiaDES(self, plain_text, chave):
        # Divide a string em blocos de 8
        bloco = [plain_text[i:i+8] for i in range(0, len(plain_text), 8)]
        bloco[-1] = bloco[-1].ljust(8)  #Adicionar preenchimento vazio no ultimo bloco, se precisar

        chave = chave.ljust(8, ".")[:8]

        # Aplica criptografia em todos os blocos, mesma chave
        bloco_criptografado = []
        for i in bloco:
            bloco_criptografado.append(self.encrypt_DES(i, chave))

        cifrado = ''.join(bloco_criptografado)

        print("\n")
        print("Texto claro: " + plain_text)
        print("Chave usada: " + chave[:8])
        print("Criptografado: " + cifrado)

        return cifrado

    # Função principal para descriptografar texto e chave
    def decriptografiaDES(self, cifra, chave): # Cifra = bloco de criptografados

        bloco = [cifra[i:i+16] for i in range(0, len(cifra), 16)]

        chave = chave.ljust(8, ".")[:8]

        bloco_decriptografado = []
        for i in bloco:
            bloco_decriptografado.append(self.decrypt_DES(i, chave))

        decifrado = ''.join(bloco_decriptografado)

        print("\n")
        print("Texto Decriptografado: " + decifrado)

        return decifrado