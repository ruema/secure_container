import os
import binascii
from itertools import count
from Crypto.Cipher import AES
import Crypto.Protocol.KDF
import Crypto.Hash

PBKDF_ALGO_PKCS5 = "pkcs5-pbkdf2-hmac-sha256"
PBKDF_ALGO_SCRYPT = "scrypt"

B32ALPHABET = b"ABCDEFGHIJKMNPQRSTUVWXYZ23456789"
B32PADDING = {
    1: (1, 2),
    3: (2, 4),
    4: (3, 1),
    6: (4, 3),
}
B32ENCODE = {
    1: (7, 2),
    2: (1, 4),
    3: (15, 1),
    4: (3, 3),
}

def _bytes_from_decode_data(s):
    if isinstance(s, str):
        try:
            return s.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError('string argument should contain only ASCII characters')
    if isinstance(s, (bytes, bytearray)):
        return s
    try:
        return memoryview(s).tobytes()
    except TypeError:
        raise TypeError("argument should be a bytes-like object or ASCII "
                        "string, not %r" % s.__class__.__name__) from None

def b32decode(s, _mapping={}):
    """Decode the Base32 encoded bytes-like object or ASCII string s.
    """
    if not _mapping:
        # Delay the initialization of the table to not waste memory
        # if the function is never called
        _mapping.update(zip(B32ALPHABET, count()))
        _mapping.update(zip(B32ALPHABET.lower(), count()))
    s = _bytes_from_decode_data(s)
    decoded = bytearray(len(s) * 5 // 8)
    try:
        idx = acc = 0
        for i, c in enumerate(s):
            acc = (acc << 5) | _mapping[c]
            if i & 7 == 7:
                decoded[idx:idx+5] = acc.to_bytes(5, 'big')
                idx += 5
                acc = 0
    except KeyError:
        raise binascii.Error('Non-base32 digit found') from None
    # Process the last, partial quanta
    if s and i & 7 < 7:
        try:
            i, j = B32PADDING[i & 7]
        except KeyError:
            raise binascii.Error('Incorrect padding')
        else:
            decoded[idx:] = (acc >> j).to_bytes(i, 'big')
    return bytes(decoded)

def b32encode(s):
    """Encode the bytes-like object s using Base32 and return a bytes object.
    """
    encoded = bytearray((len(s) * 8 + 4) // 5)
    try:
        idx = 0
        si = iter(s)
        while True:
            c = next(si)
            encoded[idx] = B32ALPHABET[c>>3]
            c = ((c & 7) << 8) | next(si) # 11 bits
            encoded[idx+1] = B32ALPHABET[c>>6]
            encoded[idx+2] = B32ALPHABET[(c>>1) & 31]
            c = ((c & 1) << 8) | next(si) # 9 bits
            encoded[idx+3] = B32ALPHABET[c>>4]
            c = ((c & 15) << 8) | next(si) # 12 bits
            encoded[idx+4] = B32ALPHABET[c>>7]
            encoded[idx+5] = B32ALPHABET[(c>>2) & 31]
            c = ((c & 3) << 8) | next(si) # 10 bits
            encoded[idx+6] = B32ALPHABET[c>>5]
            encoded[idx+7] = B32ALPHABET[c & 31]
            idx += 8
    except StopIteration:
        pass
    i = len(s) % 5
    if i > 0:
        i, j = B32ENCODE[i]
        encoded[-1] = B32ALPHABET[(c & i) << j]
    return bytes(encoded)

def derive_key(config, password):
    if config["pbkdf"] == PBKDF_ALGO_PKCS5:
        key_to_encrypt =Crypto.Protocol.KDF.PBKDF2(
            password.encode(), binascii.unhexlify(config["salt"]),
            32, config["iterations"], hmac_hash_module=Crypto.Hash.SHA256)
    elif config["pbkdf"] == PBKDF_ALGO_SCRYPT:
        key_to_encrypt = Crypto.Protocol.KDF.scrypt(
            password.encode(), binascii.unhexlify(config["salt"]),
            32, config["iterations"], config["scrypt_r"], config["scrypt_p"])
    else:
        raise ValueError("unkown pbkdf: %s" % config["pbkdf"])
    return key_to_encrypt

class SecureFs:
    def __init__(self, master_key=None, version=4, block_size=4096, iv_size=12):
        if not master_key:
            master_key = os.urandom(96)
        self.master_key = master_key
        self.version = version
        self.block_size = block_size
        self.iv_size = iv_size

    @classmethod
    def from_config(cls, config, password):
        key_to_encrypt = derive_key(config, password)
        iv = binascii.unhexlify(config["encrypted_key"]["IV"])
        data = binascii.unhexlify(config["encrypted_key"]["key"])
        mac = binascii.unhexlify(config["encrypted_key"]["MAC"])

        cipher = AES.new(key_to_encrypt, AES.MODE_GCM, nonce=iv)
        cipher.update(b'version=%d' % config['version'])
        master_key = cipher.decrypt_and_verify(data, mac)
        return cls(master_key, config['version'], config['block_size'], config['iv_size'])

    def generate_config(self, password, pbkdf_algorithm=PBKDF_ALGO_SCRYPT, rounds=65536, scrypt_p=1, scrypt_r=8):
        config = {
            "version": self.version,
            "pbkdf": pbkdf_algorithm,
            "salt": binascii.hexlify(os.urandom(32)).decode('ASCII'),
        }
        if pbkdf_algorithm == PBKDF_ALGO_PKCS5:
            config["iterations"] = rounds
        elif pbkdf_algorithm == PBKDF_ALGO_SCRYPT:
            config.update({
                "iterations": rounds,
                "scrypt_r": scrypt_r,
                "scrypt_p": scrypt_p,
            })
        else:
            raise RuntimeError("Unknown pbkdf algorithm " + pbkdf_algorithm)
        key_to_encrypt = derive_key(config, password)
        iv = os.urandom(32)
        cipher = AES.new(key_to_encrypt, AES.MODE_GCM, nonce=iv)
        cipher.update(b'version=%d' % config['version'])
        encrypted_master_key, mac = cipher.encrypt_and_digest(self.master_key)
        config["encrypted_key"] = {
            "IV": binascii.hexlify(iv).decode('ASCII'),
            "MAC": binascii.hexlify(mac).decode('ASCII'),
            "key": binascii.hexlify(encrypted_master_key).decode('ASCII'),
        }
        if self.version >= 2:
            config["block_size"] = self.block_size
            config["iv_size"] = self.iv_size
        return config

    def decrypt_filename(self, filename):
        data = b32decode(filename)
        siv = AES.new(self.master_key[:32], AES.MODE_SIV)
        return siv.decrypt_and_verify(data[16:], data[:16]).decode()

    def encrypt_filename(self, filename):
        siv = AES.new(self.master_key[:32], AES.MODE_SIV)
        ciphertext, mac = siv.encrypt_and_digest(filename.encode())
        return b32encode(mac + ciphertext).decode()

    def open(self, filename, mode='rb'):
        stream = open(filename, mode)
        return AESGCMCryptStream(stream, self.master_key[32:64],
            self.block_size, self.iv_size)

class AESGCMCryptStream:
    MAC_SIZE = 16
    HEADER_SIZE = 16
    MAX_BLOCKS = (1<<31) - 1

    def __init__(self, stream, master_key, block_size, iv_size):
        self.block_size = block_size
        self.stream = stream
        self.iv_size = iv_size
        if not 12 <= iv_size <= 32:
            raise ValueError("IV size too small or too large")
        if block_size < 32:
            raise ValueError("Block size too small")
        self.header = self.stream.read(self.HEADER_SIZE)
        if not self.header:
            self.header = os.urandom(self.HEADER_SIZE)
        elif len(self.header) != self.HEADER_SIZE:
            raise RuntimeError("Underlying stream has invalid header size")
        ecenc = AES.new(master_key, mode=AES.MODE_ECB)
        self.session_key = ecenc.encrypt(self.header)

    def close(self):
        self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    underlying_block_size = property(lambda self: self.block_size + self.iv_size + self.MAC_SIZE)

    def read_block(self, block_number):
        if block_number > self.MAX_BLOCKS:
            raise IndexError()
        underlying_block_size = self.underlying_block_size
        self.stream.seek(self.HEADER_SIZE + underlying_block_size * block_number)
        block = self.stream.read(underlying_block_size)
        if len(block) < self.MAC_SIZE + self.iv_size:
            return b""
        mac = block[-self.MAC_SIZE:]
        iv = block[:self.iv_size]
        block = block[self.iv_size:-self.MAC_SIZE]
        if sum(iv) == 0 and sum(mac)== 0 and sum(block) == 0:
            return block
        decryptor = AES.new(self.session_key, mode=AES.MODE_GCM, nonce=iv)
        decryptor.update(block_number.to_bytes(4, 'little'))
        block = decryptor.decrypt_and_verify(block, mac)
        return block

    def write_block(self, block_number, block):
        if block_number > self.MAX_BLOCKS:
            raise IndexError()
        iv = os.urandom(self.iv_size)
        encryptor = AES.new(self.session_key, mode=AES.MODE_GCM, nonce=iv)
        encryptor.update(block_number.to_bytes(4, 'little'))
        block, mac = encryptor.encrypt_and_verify(block)
        underlying_block_size = self.underlying_block_size
        if self.stream.tell() == 0:
            self.stream.write(self.header)
        self.stream.seek(self.HEADER_SIZE + underlying_block_size * block_number)
        self.stream.write(iv + block + mac)

    def size(self):
        size = os.fstat(self.stream.fileno()).st_size - self.HEADER_SIZE
        if size < 0:
            return 0
        num_blocks, residue = divmod(size, self.underlying_block_size)
        residue -= self.iv_size + self.MAC_SIZE
        return num_blocks * self.block_size +  max(0, residue)
