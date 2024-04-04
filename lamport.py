import hashlib
from os import urandom

class LamportSignature:
    def __init__(self):
        self.private_key = self.generate_private_key()
        self.public_key = self.generate_public_key()

    @staticmethod
    def generate_private_key():
        return [(bytearray(urandom(32)), bytearray(urandom(32))) for _ in range(256)]

    def generate_public_key(self):
        return [(self.hash(a), self.hash(b)) for a, b in self.private_key]

    @staticmethod
    def gather_keys(key_list):
        ret = bytearray(0)
        
        for a, b in key_list:
            ret += a + b
                
        return ret

    @staticmethod
    def scatter_key(key):
        match len(key):
            case 8192:
                return [key[i:i + 32] for i in range(0, 8192, 32)]

            case 16384:
                return [(key[i:i + 32], key[i + 32:i + 64]) for i in range(0, 16384, 64)]

        raise ValueError('Dimensiunea invalida pentru cheie.')

    def get_key(self, is_public):
        key = self.public_key if is_public else self.private_key
        return self.gather_keys(key)

    def sign(self, msg):
        msg_hash_bin = f'{int(self.hash(msg).hex(), 16):b}'        
        return [a if bit == '0' else b for (a, b), bit in zip(self.private_key, msg_hash_bin)]

    @classmethod
    def verify(cls, msg, signature, public_key):
        public_key = cls.scatter_key(public_key)
        msg_hash_bin = f'{int(cls.hash(msg).hex(), 16):b}'
        signature_hashes = [cls.hash(i) for i in signature]
        
        for sig_hash, (a, b), bit in zip(signature_hashes, public_key, msg_hash_bin):
            if (bit == '0' and sig_hash != a) or (bit == '1' and sig_hash != b):
                return False
            
        return True

    @staticmethod
    def hash(data):
        if type(data) is not bytearray:
            data = data.encode('utf-8')

        return bytearray(hashlib.sha256(data).digest())