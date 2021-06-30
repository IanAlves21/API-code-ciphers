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

class AES:
    async def encrypt(self, request: Request):
        # # INPUT para texto claro
        plain_text = "TesteCriptografia para passar na matéria de criptografia"


        # INPUT para O TAMANHO
        tamanho_chave = 128


        # INPUT para chave
        chave = "chave12345678910chave12345678910"
        # chave = "chave124"
        cifra = self.criptografiaAES(plain_text, chave, tamanho_chave)

        decifrado = self.decriptografiaAES("\r³´£_û\u000b'îY¢¶^ko¿à¾Õð'G\"ì÷%ºÎý;·qP°P÷¿<¯¹òüÜ*Ï", chave, tamanho_chave)
        print("cifra ----------------------------------------------> " + cifra)
        print("aquiiiiii -------------------------------------------------> " + decifrado)

        return json({'message': cifra})

    def encrypt_AES(self, plain_text, chave, tamanho = 128):
        # DICIONARIOS DE RODADAS PARA CADA TAMANHO INCIAIS
        n_rodada_dic = {128: 10, 192: 12, 256: 14}
        rodada_final_dic = {128: 40, 192: 48, 256: 56}

        # CONVERTE TEXTO CLARO EM BINARIO
        plain_text_bin = ""
        temp = ""
        for i in plain_text: #Converte string ascii em Hex
            temp = temp + str(hex(ord(i)))[2:].zfill(2)

        for i in temp: # Transforma Hex em string de binario equivalente
            plain_text_bin = plain_text_bin + str(format(int(i, 16), '04b'))

        # GERAR CHAVES

        lista_chaves = self.gerar_chaves_geral(chave, tamanho)

        # =============================================CRIPTOGFAFIA=============================================
        # AddRoundKey Inicial
        temp_texto = self.AddRoundKey(plain_text_bin, lista_chaves[0:4])

        # print(temp_texto)

        # Rodadas 1 a 9/11/13
        for rodada in range(1,n_rodada_dic[tamanho]):
            # print(rodada)
            # SubBytes
            for i in range(len(temp_texto)):
                temp_texto[i] = self.CaixaS(temp_texto[i], False)

            #ShiftRows
            temp_texto = self.ShiftRow(temp_texto, False)

            #MixColumns
            temp_texto = self.MixColumns(temp_texto, False)

            # Chave da rodada
            temp_texto = self.AddRoundKey(''.join(temp_texto), lista_chaves[rodada*4: (rodada+1)*4]) #Texto unificado e chave
            
            # print(temp_texto)

        # Rodada 10

        # SubBytes
        for i in range(len(temp_texto)):
            temp_texto[i] = self.CaixaS(temp_texto[i])

        #ShiftRows
        temp_texto = self.ShiftRow(temp_texto)

        # Chave da rodada
        temp_texto = self.AddRoundKey(''.join(temp_texto), lista_chaves[rodada_final_dic[tamanho]: rodada_final_dic[tamanho] + 4])

        #TEXTO CIFRADO EM BINÁRIO
        cifra = temp_texto

        # Conversão de binário para hexadecimal
        output_bin = str(hex(int(''.join(cifra), 2))).upper()[2:].zfill(32)
        #Conversão hexadecimal para ascii

        cifra_ascii = ""

        for i in range(len(output_bin)//2):
            cifra_ascii = cifra_ascii + chr(int(output_bin[i*2:(i+1)*2],16))

        return cifra_ascii

    def decrypt_AES(self, cifra, chave, tamanho = 128):
        # DICIONARIO DE RODADAS PARA CADA TAMANHO
        n_rodada_dic = {128: 10, 192: 12, 256: 14}
        rodada_final_dic = {128: 40, 192: 48, 256: 56}

        # CONVERTE CIFRA EM BINARIO
        plain_cifra_bin = ""
        temp = ""
        for i in cifra: #Converte string ascii em Hex
            temp = temp + str(hex(ord(i)))[2:].zfill(2)

        for i in temp: # Transforma Hex em string de binario equivalente
            plain_cifra_bin = plain_cifra_bin + str(format(int(i, 16), '04b'))

        # GERAR CHAVES

        lista_chaves = self.gerar_chaves_geral(chave, tamanho)

        #=============================================DECRIPTOGFAFIA==================================================

        # AddRoundKey Inicial
        temp_cifra = self.AddRoundKey(''.join(plain_cifra_bin), lista_chaves[rodada_final_dic[tamanho]: rodada_final_dic[tamanho] + 4])

        # print(temp_cifra)

        # Rodadas 1 a 9
        for rodada in reversed(range(1,n_rodada_dic[tamanho])):
            #ShiftRows
            temp_cifra = self.ShiftRow(temp_cifra, True)

            # SubBytes
            for i in range(len(temp_cifra)):
                temp_cifra[i] = self.CaixaS(temp_cifra[i], True)

            # Chave da rodada
            temp_cifra = self.AddRoundKey(''.join(temp_cifra), lista_chaves[(rodada)*4: (rodada+1)*4]) #Texto unificado e chave

            #MixColumns
            temp_cifra = self.MixColumns(temp_cifra, True)
            
        # Rodada 10

        #ShiftRows
        temp_cifra = self.ShiftRow(temp_cifra, True)

        # SubBytes
        for i in range(len(temp_cifra)):
            temp_cifra[i] = self.CaixaS(temp_cifra[i], True)

        # Chave da rodada
        temp_cifra = self.AddRoundKey(''.join(temp_cifra), lista_chaves[0: 4]) #Texto unificado e chave

        # TEXTO DECIFRADO
        decifrado = temp_cifra

        # Conversão de binário para hexadecimal
        output_bin = str(hex(int(''.join(decifrado), 2))).upper()[2:].zfill(32)
        #Conversão hexadecimal para ascii
        decifra_ascii = ""
        for i in range(len(output_bin)//2):
            decifra_ascii = decifra_ascii + chr(int(output_bin[i*2:(i+1)*2],16))

        return decifra_ascii

    def CaixaS (self, word, invertido = False): 
        caixa_s =[   [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
                    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
                    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
                    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
                    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
                    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
                    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
                    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
                    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
                    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
                    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
                    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
                    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
                    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
                    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
                    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]
                
        caixa_s_inv = [
                [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
                [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
                [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
                [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
                [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
                [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
                [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
                [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
                [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
                [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
                [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
                [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
                [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
                [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
                [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
                [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]]

        temp_word = []

        for i in range(0, len(word), 8):
            temp_word.append(word[i: 8+i])

        # Converte string de binário em decimal e passa pela caixa s
        # o primeiro nimble é a linha, o segundo é a coluna
        # [2:] do final remove o 0x do início
        # zfill garante que o hexadecimal tenha 2 digitos
        # Faz isso para cada byte dos 32 bits
        temp = []
        if(invertido):
            for i in temp_word:
                temp.append(hex(caixa_s_inv[int(i[0:4],2)][int(i[4:8],2)])[2:].zfill(2))
        else:
            for i in temp_word:
                temp.append(hex(caixa_s[int(i[0:4],2)][int(i[4:8],2)])[2:].zfill(2))

        # Junta os bytes convertidos em 32 bits novamente
        temp_text = ""
        for i in temp: 
            for j in i:
                temp_text = temp_text + str(format(int(j, 16), '04b'))

        return ''.join(temp_text)

    def Rcon(self, rodada):
        # 30 rodadas possíveis
        R_con = [   0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 
                    0x9a, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5]

        #Rcon retorna o numero da tabela como o primeiro byte e 0 nos 3 bytes seguintes
        #Ljust preenche até que tenha 10 digitos e [2:] remove o 0x
        temp = hex(R_con[rodada-1]).ljust(10, "0")[2:]

        temp_text = ""
        for i in temp: # Transforma Hex em string de binario equivalente
            temp_text = temp_text + str(format(int(i, 16), '04b'))

        return temp_text

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

    # Faz a mistura do texto e da chave ==================================================================================================================
    # Texto de 128 bits e lista de 4 chaves 
    # Saída: texto e chave misturado separados em 32 bits
    def AddRoundKey(self, plain_text_bin, lista_chaves):
        temp = []
        for i in range(0, len(plain_text_bin), 32):
            temp.append(plain_text_bin[i: 32+i])

        for i in range(0, len(temp)):
            temp[i] = self.funcXOR(temp[i], lista_chaves[i])

        return temp

    # Em uma matriz de bytes, faz um shift na linha da matriz, ==========================================================================================
    # Linha 0, shift 0, linha 1, shift 0 e assim por diante
    # Inverso faz o shift para direita
    def ShiftRow(self, texto, inverso = False):
        # CONVERTER TEXTO EM MATRIZ HEX EQUIVALENTE
        texto = ''.join(texto)
        temp = []
        for i in range(0, len(texto), 8):
            temp.append(texto[i: 8+i])

        # print(temp)
        temp = np.transpose(np.reshape(temp, (-1, 4))).tolist()

        # SHIFT
        if(inverso == False):
            for i in range(4): # Shift para esquerda
                temp[i] = self.shift_esquerda(temp[i], i)
        else:
            for i in range(4): #Shift para direita
                temp[i] = self.shift_esquerda(temp[i], -i)

        # CONVERTER MATRIZ HEX EQUIVALENTE EM TEXTO
        temp = np.transpose(temp).flatten().tolist()
        temp = ''.join(temp)
        temp1 = []
        for i in range(0, len(temp), 32):
            temp1.append(temp[i: 32+i])

        return temp1

    def byte_mul(self, a, b):
        p = 0
        for c in range(8):
            if b & 1:
                p ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b
            b >>= 1

        # Converte hexadecimal resultante em binario
        plain_text_bin = ""
        for i in hex(p)[2:].zfill(2): # Transforma Hex em string de binario equivalente
            plain_text_bin = plain_text_bin + str(format(int(i, 16), '04b'))
        return plain_text_bin

    #Entrada = Texto claro divido em 4 words, saida: 4 words
    # Faz uma multiplicação de matrizes, no entanto:
    # Ao invés de multiplicar, usa-se byte_mul
    # Ao invés de somar, usa-se XOR
    # Inverso ou não muda apenas a matriz padrão
    def MixColumns(self, texto, inverso = False):
        if(inverso == False):
            a = [   [0x02, 0x03, 0x01, 0x01], [0x01, 0x02, 0x03, 0x01],
                    [0x01, 0x01, 0x02, 0x03], [0x03, 0x01, 0x01, 0x02]] # Matriz padrão de multiplicacao
        else:
            a =[    [0x0e, 0x0b, 0x0d, 0x09], [0x09, 0x0e, 0x0b, 0x0d],
                    [0x0d, 0x09, 0x0e, 0x0b], [0x0b, 0x0d, 0x09, 0x0e]] # Matriz padrão de multiplicacao inversa


        # b = [[0x87, 0xf2, 0x4d, 0x97], [0x6e, 0x4c, 0x90, 0xec], [0x46, 0xe7, 0x4a, 0xc3], [0xa6, 0x8c, 0xd8, 0x95]]
        c = [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]] # Matriz a ser preenchida

        # CONVERSÃO TEXTO EM MATRIZ EQUIVALENTE HEXADECIMAL
        texto = ''.join(texto)
        temp = []
        for i in range(0, len(texto), 8):
            temp.append(str(hex(int(texto[i: 8+i], 2))).upper()[2:].zfill(2))
        matriz = np.transpose(np.reshape(temp, (-1, 4))).tolist()

        # Multiplicação de matrizes, só que com func de xor ao invés de soma e byte_mul ao invés de multiplicação
        temp_xor = "00000000"
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    temp_xor = self.funcXOR(temp_xor, self.byte_mul(a[i][k], int(matriz[k][j], 16)))


                c[i][j] = temp_xor
                temp_xor = "00000000"


        # CONVERTER MATRIZ HEX EQUIVALENTE EM TEXTO
        c = np.transpose(c).flatten().tolist()
        c = ''.join(c)
        temp1 = []
        for i in range(0, len(c), 32):
            temp1.append(c[i: 32+i])

        return temp1

    # Gera uma lista de chaves a partir do binario
    # Entrada: Chave de 16,24,32 bytes = 128, 192, 256 bits
    # Saída:  10 chaves geradas(11 words), 12 (13 words), 14 (15 words) 
    def gerar_chaves_geral (self, chave_inicial, tamanho = 128): 

        # ================ CONVERTE CHAVE EM BINARIO ==============
        chave_bin = ""
        temp = ""
        for i in chave_inicial: #Converte string ascii em Hex
            temp = temp + str(hex(ord(i)))[2:].zfill(2)

        for i in temp: # Transforma Hex em string de binario equivalente
            chave_bin = chave_bin + str(format(int(i, 16), '04b'))

        # ==================GERAR CHAVES A PARTIR DO BINÁRIO ===========================

        # 4 para 128bits, 6 para 192bits, 8 para 256bits
        lista_chaves = []

        # Chaves iniciais, dividir em partes iguais de 32 bits
        # Pode ser divido em 4, 6 ou 8 partes dependendo do tamanho da chave inicial
        for i in range(0, len(chave_bin), 32):
            lista_chaves.append(chave_bin[i: 32+i])


        tamanho_dicionario = {128: 44, 192: 52, 256: 60}    # Dicionario para o n de chaves final
        n_chave_inicial = tamanho//32                       # Qt de chaves que a chave inicial tem

        #Gera 40/48/56 chaves a partir dos 4/6/8 words originais
        # https://en.wikipedia.org/wiki/AES_key_schedule#cite_note-3
        # Explicação do que acontece aqui
        for i in range(n_chave_inicial, tamanho_dicionario[tamanho]):
            temp = lista_chaves[i - 1]
            
            if ((i % 4 == 0) and i >= n_chave_inicial):
                temp = self.CaixaS(self.shift_esquerda(temp, 4), False)
                temp = self.funcXOR(temp, self.Rcon(int(i/n_chave_inicial)-1))
            elif((i % 4 == 0) and n_chave_inicial == 8 and i >= n_chave_inicial):
                temp = self.CaixaS(temp, False)
            
            lista_chaves.append(self.funcXOR(lista_chaves[i - 4], temp))


        return lista_chaves

    # Função principal para criptografar texto e chave
    def criptografiaAES(self, plain_text, chave, tamanho):
        # Divide a string em blocos de 128bits
        bloco = [plain_text[i:i+16] for i in range(0, len(plain_text), 16)]
        bloco[-1] = bloco[-1].ljust(16)  #Adicionar preenchimento vazio no ultimo bloco, se precisar

        chave = chave.ljust(tamanho//8, ".")[:tamanho//8]

        # Aplica criptografia em todos os blocos, mesma chave
        bloco_criptografado = []
        for i in bloco:
            bloco_criptografado.append(self.encrypt_AES(i, chave, tamanho))

        print("\n")
        print("Texto claro: " + plain_text)
        print("Chave usada: " + chave[:tamanho//8]) # N de chr ASCII usados
        criptografado = ''.join(bloco_criptografado)
        print("Criptografado: ")
        print(criptografado)

        return criptografado

    # Função principal para descriptografar texto e chave
    def decriptografiaAES(self, cifra, chave, tamanho): # Cifra = bloco de criptografados

        # Divide a string em blocos de 128bits
        bloco = [cifra[i:i+16] for i in range(0, len(cifra), 16)]
        bloco[-1] = bloco[-1].ljust(16)  #Adicionar preenchimento vazio no ultimo bloco, se precisar
        
        # Garante que a chave tenha o numero minimo de caracteres ascii de acordo com o tamanho
        chave = chave.ljust(tamanho//8, ".")[:tamanho//8]

        # Pega os blocos criptografados e decriptografa cada parte
        bloco_decriptografado = []
        for i in bloco:
            bloco_decriptografado.append(self.decrypt_AES(i, chave, tamanho))

        print("\n")
        descriptografado = ''.join(bloco_decriptografado)
        print("Texto Decriptografado: " + descriptografado)

        return descriptografado