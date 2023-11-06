from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from charm.core.engine.util import *
from charm.toolbox.msp import MSP
import pickle
import json


class Serialize:
    def __init__(self):
        self.group = PairingGroup('SS512')
        self.util = MSP

    # Serialize public key
    def serialize_pk(self, pk):
        pk['h_A'] = list(map(self.group.serialize, pk['h_A']))
        pk['e_gh_kA'] = list(map(self.group.serialize, pk['e_gh_kA']))
        return pk
    # Deserialize public key
    def deserialize_pk(self, pk):
        pk['h_A'] = list(map(self.group.deserialize, pk['h_A']))
        pk['e_gh_kA'] = list(map(self.group.deserialize, pk['e_gh_kA']))
        return pk
    # Save public key
    def save_file_pk(self, pk, filename):
        keyser = self.serialize_pk(pk)
        encryptedfile = open(filename, 'wb')
        pickle.dump(keyser, encryptedfile)
        encryptedfile.close()
    # Load public key
    def load_file_pk(self, filename):
        encryptedfile = open(filename, 'rb')
        keydeser = pickle.load(encryptedfile)
        keydeser = self.deserialize_pk(keydeser)
        return keydeser
    # Jsonify public key
    def jsonify_pk(self, pk):
        pk = self.serialize_pk(pk)
        pk['e_gh_kA'] = list(map(lambda x: x.decode('utf-8'), pk['e_gh_kA']))
        pk['h_A'] = list(map(lambda x: x.decode('utf-8'), pk['h_A']))
        return json.dumps(pk)
    # Unjsonify public key
    def unjsonify_pk(self, pk):
        pk = json.loads(pk)
        pk['e_gh_kA'] = list(map(lambda x: x.encode('utf-8'), pk['e_gh_kA']))
        pk['h_A'] = list(map(lambda x: x.encode('utf-8'), pk['h_A']))
        return self.deserialize_pk(pk)
    
    # Serialize master key
    def serialize_mk(self, mk):
        mk['g'] = self.group.serialize(mk['g'])
        mk['h'] = self.group.serialize(mk['h'])
        mk['g_k'] = list(map(self.group.serialize, mk['g_k']))
        mk['A'] = list(map(self.group.serialize, mk['A']))
        mk['B'] = list(map(self.group.serialize, mk['B']))
        return mk
    # Deserialize master key
    def deserialize_mk(self, mk):
        mk['g'] = self.group.deserialize(mk['g'])
        mk['h'] = self.group.deserialize(mk['h'])
        mk['g_k'] = list(map(self.group.deserialize, mk['g_k']))
        mk['A'] = list(map(self.group.deserialize, mk['A']))
        mk['B'] = list(map(self.group.deserialize, mk['B']))
        return mk
    # Save master key
    def save_file_mk(self, mk, filename):
        keyser = self.serialize_mk(mk)
        encryptedfile = open(filename, 'wb')
        pickle.dump(keyser, encryptedfile)
        encryptedfile.close()
    # Load master key
    def load_file_mk(self, filename):
        encryptedfile = open(filename, 'rb')
        keydeser = pickle.load(encryptedfile)
        keydeser = self.deserialize_mk(keydeser)
        return keydeser
    # Jsonify master key
    def jsonify_mk(self, mk):
        mk = self.serialize_mk(mk)
        mk['g'] = mk['g'].decode('utf-8')
        mk['h'] = mk['h'].decode('utf-8')
        mk['g_k'] = list(map(lambda x: x.decode('utf-8'), mk['g_k']))
        mk['A'] = list(map(lambda x: x.decode('utf-8'), mk['A']))
        mk['B'] = list(map(lambda x: x.decode('utf-8'), mk['B']))
        return json.dumps(mk)
    # Unjsonify master key
    def unjsonify_mk(self, mk):
        mk = json.loads(mk)
        mk['g'] = mk['g'].encode('utf-8')
        mk['h'] = mk['h'].encode('utf-8')
        mk['g_k'] = list(map(lambda x: x.encode('utf-8'), mk['g_k']))
        mk['A'] = list(map(lambda x: x.encode('utf-8'), mk['A']))
        mk['B'] = list(map(lambda x: x.encode('utf-8'), mk['B']))
        return self.deserialize_mk(mk)
    
    # Serialize secret key (private key)
    def serialize_sk(self, sk):
        sk['attr_list'] = list(map(lambda x: x.encode('utf-8'), sk['attr_list']))
        sk['K_0'] = list(map(self.group.serialize, sk['K_0']))
        for dict_key, value in sk['K'].items():
            for tuple_index, value in enumerate(sk['K'][dict_key]):
                sk['K'][dict_key][tuple_index] = self.group.serialize(
                    value)
        sk['Kp'] = list(map(self.group.serialize, sk['Kp']))
        return sk
    # Deserialize secret key (private key)
    def deserialize_sk(self, sk):
        sk['attr_list'] = list(map(lambda x: x.decode('utf-8'), sk['attr_list']))
        sk['K_0'] = list(map(self.group.deserialize, sk['K_0']))
        for dict_key, value in sk['K'].items():
            for tuple_index, value in enumerate(sk['K'][dict_key]):
                sk['K'][dict_key][tuple_index] = self.group.deserialize(
                    value)
        sk['Kp'] = list(map(self.group.deserialize, sk['Kp']))
        return sk
    # Jsonify secret key (private key)
    def jsonify_sk(self, sk):
        sk = self.serialize_sk(sk)
        sk['attr_list'] = list(map(lambda x: x.decode('utf-8'), sk['attr_list']))
        sk['K_0'] = list(map(lambda x: x.decode('utf-8'), sk['K_0']))
        for dict_key, value in sk['K'].items():
            for tuple_index, value in enumerate(sk['K'][dict_key]):
                sk['K'][dict_key][tuple_index] = value.decode('utf-8')
        sk['Kp'] = list(map(lambda x: x.decode('utf-8'), sk['Kp']))
        return json.dumps(sk)
    # Unjsonify secret key (private key)
    def unjsonify_sk(self, sk):
        sk = json.loads(sk)
        sk['attr_list'] = list(map(lambda x: x.encode('utf-8'), sk['attr_list']))
        sk['K_0'] = list(map(lambda x: x.encode('utf-8'), sk['K_0']))
        for dict_key, value in sk['K'].items():
            for tuple_index, value in enumerate(sk['K'][dict_key]):
                sk['K'][dict_key][tuple_index] = value.encode('utf-8')
        sk['Kp'] = list(map(lambda x: x.encode('utf-8'), sk['Kp']))
        return self.deserialize_sk(sk)
    
    # Serialize ciphertext
    def serialize_ctxt(self, ctxt):
        ctxt['policy'] = ctxt['policy'].__str__()
        ctxt['Cp'] = self.group.serialize(ctxt['Cp'])
        ctxt['C_0'] = list(map(self.group.serialize, ctxt['C_0']))
        for dict_key, value in ctxt['C'].items():
            for tuple_index, value in enumerate(ctxt['C'][dict_key]):
                ctxt['C'][dict_key][tuple_index] = self.group.serialize(
                    value)
        return ctxt
    # Deserialize ciphertext
    def deserialize_ctxt(self, ctxt):
        ctxt['policy'] = self.util.createPolicy(MSP,policy_string=ctxt['policy'])
        ctxt['Cp'] = self.group.deserialize(ctxt['Cp'])
        ctxt['C_0'] = list(map(self.group.deserialize, ctxt['C_0']))
        for dict_key, value in ctxt['C'].items():
            for tuple_index, value in enumerate(ctxt['C'][dict_key]):
                ctxt['C'][dict_key][tuple_index] = self.group.deserialize(
                    value)
        return ctxt
    # Jsonify ciphertext
    def jsonify_ctxt(self, ctxt):
        ctxt = self.serialize_ctxt(ctxt)
        ctxt['Cp'] = ctxt['Cp'].decode('utf-8')
        ctxt['C_0'] = list(map(lambda x: x.decode('utf-8'), ctxt['C_0']))
        for dict_key, value in ctxt['C'].items():
            for tuple_index, value in enumerate(ctxt['C'][dict_key]):
                ctxt['C'][dict_key][tuple_index] = value.decode('utf-8')
        return json.dumps(ctxt)
    # Unjsonify ciphertext
    def unjsonify_ctxt(self, ctxt):
        ctxt = json.loads(ctxt)
        ctxt['Cp'] = ctxt['Cp'].encode('utf-8')
        ctxt['C_0'] = list(map(lambda x: x.encode('utf-8'), ctxt['C_0']))
        for dict_key, value in ctxt['C'].items():
            for tuple_index, value in enumerate(ctxt['C'][dict_key]):
                ctxt['C'][dict_key][tuple_index] = value.encode('utf-8')
        return self.deserialize_ctxt(ctxt)