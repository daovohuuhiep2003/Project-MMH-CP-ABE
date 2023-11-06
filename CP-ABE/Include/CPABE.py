from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from charm.core.engine.util import *
from charm.schemes.abenc.ac17 import AC17CPABE
from . import SerializeAC17 as ac17
from Crypto.Cipher import AES 
import hashlib , base64
import os
import struct

class CP_ABE:
    def __init__(self):
        self.groupObj = PairingGroup('SS512')
        self.cpabe = AC17CPABE(self.groupObj,2)
    
    # Hàm mã hoá msg
    def ABEencryption(self, filename, pk, policy):
        # Mở file chứa PHR cần mã hoá
        msg = open(filename,"rb").read()
        serialize_encoder = ac17.Serialize()

        # Tạo key AES dùng dùng để mã hoá msg
        key = self.groupObj.random(GT)

        # Mã hoá key AES bằng CP-ABE
        encrypt_key = self.cpabe.encrypt(pk, key, policy)

        #Đóng gói key
        encrypt_key_byte = serialize_encoder.jsonify_ctxt(encrypt_key)
        encrypt_key_byte = base64.b64encode(encrypt_key_byte.encode())
        encrypt_key_size = len(encrypt_key_byte)
        stream = struct.pack('Q',encrypt_key_size)

        # Mã hoá msg bằng aes với key vừa tạo
        aes_key = hashlib.sha256(str(key).encode()).digest()
        iv = os.urandom(16)
        encryptor = AES.new(aes_key,AES.MODE_CFB,iv)
        encrypted_data = encryptor.encrypt(msg)

        # Xuất ra output để gửi đi
        output = stream + iv + encrypt_key_byte + encrypted_data
        return output

    # Hàm giải mã ciphertext
    def ABEdecryption(self, filename, pk, sk):
        serialize_encoder = ac17.Serialize()

        # Mở file chứa input gồm (stream + iv + encrypt_key_byte + encrypted_data) và tách các trường
        ciphertext_stream = open(filename,"rb")
        encrypt_key_size = struct.unpack('Q',ciphertext_stream.read(struct.calcsize('Q')))[0]
        ciphertext_stream.close()
        ciphertext = open(filename,"rb").read()
        iv = ciphertext[8:24]
        encrypt_key_byte = ciphertext[24:encrypt_key_size+24]
        encrypt_key_byte = base64.b64decode(encrypt_key_byte)
        encrypt_key = serialize_encoder.unjsonify_ctxt(encrypt_key_byte)

        # Giải mã key AES
        key = self.cpabe.decrypt(pk,encrypt_key,sk)

        # Giải mã ciphertext được mã hoá bằng AES từ key đã giải mã trên
        if(key):
            aes_key = hashlib.sha256(str(key).encode()).digest()
            encryptor = AES.new(aes_key,AES.MODE_CFB,iv)
            decrypted_data = encryptor.decrypt(ciphertext[8+16+encrypt_key_size:])

            return decrypted_data
        else:
            return None

    # Tạo publickey và master_key
    def KeyGen(self):
        (pk,mk) = self.cpabe.setup()
        return pk,mk
    #Tạo private_key 
    def PrivateKeyGen(self, pk, mk, attribute):
        sk = self.cpabe.keygen(pk, mk, attribute)
        return sk 
