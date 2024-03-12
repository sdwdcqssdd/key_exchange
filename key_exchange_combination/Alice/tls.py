import hashlib
import struct, os, pickle
from enum import Enum, IntEnum

from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
    x448,
    x25519,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

C1 = b""
L1 = b"c hs traffic"
L2 = b"s hs traffic"
L3 = b"derived"
L4 = b"traffic key"
L5 = b"tls 1.3, server certificate verify"
L6 = b"finished"
L7 = b"tls 1.3, client certificate verify"
L8 = b"s ap traffic"
L9 = b"c ap traffic"

def key_extra(
    algorithm: hashes.HashAlgorithm, salt: bytes, key_material: bytes
) -> bytes:
    h = hmac.HMAC(salt, algorithm)
    h.update(key_material)
    return h.finalize()

def PRF(secret, seed, length):
    backend = default_backend()
    result = b""
    A = seed

    while len(result) < length:
        h = hmac.HMAC(secret, hashes.SHA256(), backend=backend)
        h.update(A)
        A = h.finalize()
        h = hmac.HMAC(secret, hashes.SHA256(), backend=backend)
        h.update(A + seed)
        result += h.finalize()

    return result[:length]

def encrypt_data(key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return iv + ct
def decrypt_data(key, data):
    iv = data[:16]
    actual_data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(actual_data) + decryptor.finalize()
    return decrypted_data

class Context():
    def __init__(self, is_client, cert_bytes, priv_bytes) -> None:
        self.is_client = is_client
        self.nonce = None
        self.ec_private_key = None
        self.ec_public_key = None
        self.state = None
        self.cert_bytes = cert_bytes
        self.certificate: Optional[x509.Certificate] = x509.load_pem_x509_certificate(cert_bytes)
        self.certificate_private_key: Optional[
            Union[dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]
        ] = serialization.load_pem_private_key(data=priv_bytes, password=None)
        self.peer_cert_bytes = None
        self.peer_cert = None
        self.peer_cert_public_key = None
        self.peer_ec_public_key = None
        self.peer_nonce = None
        self.handshake_secret = None
        self.handshake_traffic_secret = None
        self.peer_handshake_traffic_secret = None
        self.traffic_key = None
        self.peer_traffic_key = None
        self.dhe = None
        self.dhs = None
        self.hash = hashes.Hash(hashes.SHA256())
        self.hello = None
        self.peer_hello = None
        self.hello_bytes = None
        self.peer_hello_bytes = None
        self.fk = None
        self.peer_fk = None
        self.sig = None
        self.peer_sig = None
        self.finish = None
        self.peer_finish = None
        self.master_secret = None
        self.ats = None
        self.peer_ats = None
        self.nonce = os.urandom(32)

    def server_send_cert(self):
        H = self.hash.copy()
        H.update(self.peer_hello_bytes)
        H.update(self.hello_bytes)
        H.update(self.cert_bytes)
        context_hash = H.finalize()
        self.sig = self.certificate_private_key.sign(data=context_hash,
                                                     padding=padding.PSS(
                                                         mgf=padding.MGF1(hashes.SHA256()),
                                                         salt_length=padding.PSS.MAX_LENGTH
                                                     ),
                                                     algorithm=hashes.SHA256())

        H = self.hash.copy()
        H.update(b'')
        empty_hash = H.finalize()
        self.fk= PRF(
            secret=self.handshake_secret,
            seed=L2 + empty_hash,
            length=32)
        self.peer_fk = PRF(
            secret=self.handshake_secret,
            seed=L2 + empty_hash,
            length=32)
        H = self.hash.copy()
        H.update(self.peer_hello_bytes)
        H.update(self.hello_bytes)
        H.update(self.cert_bytes)
        H.update(self.sig)
        context_hash = H.finalize()
        hmac_ = hmac.HMAC(key=self.fk, algorithm=hashes.SHA256())
        hmac_.update(context_hash)
        self.finish = hmac_.finalize()
        return self.cert_bytes, self.sig, self.finish

    def client_send_cert(self):
        H = self.hash.copy()
        H.update(self.hello_bytes)
        H.update(self.peer_hello_bytes)
        H.update(self.cert_bytes)
        context_hash = H.finalize()
        self.sig = self.certificate_private_key.sign(data=context_hash,
                                                     padding=padding.PSS(
                                                         mgf=padding.MGF1(hashes.SHA256()),
                                                         salt_length=padding.PSS.MAX_LENGTH
                                                     ),
                                                     algorithm=hashes.SHA256())

        H = self.hash.copy()
        H.update(self.hello_bytes)
        H.update(self.peer_hello_bytes)
        H.update(self.cert_bytes)
        H.update(self.sig)
        context_hash = H.finalize()
        hmac_ = hmac.HMAC(key=self.fk, algorithm=hashes.SHA256())
        hmac_.update(context_hash)
        self.finish = hmac_.finalize()
        return self.cert_bytes, self.sig, self.finish

    def client_verify_cert(self, peer_cert_bytes, peer_sig, peer_finish):
        self.peer_cert_bytes = peer_cert_bytes
        self.peer_sig = peer_sig
        self.peer_finish = peer_finish

        H = self.hash.copy()
        H.update(b'')
        empty_hash = H.finalize()
        self.fk = PRF(
            secret=self.handshake_secret,
            seed=L2 + empty_hash,
            length=32)
        self.peer_fk = PRF(
            secret=self.handshake_secret,
            seed=L2 + empty_hash,
            length=32)
        self.peer_cert = x509.load_pem_x509_certificate(peer_cert_bytes)
        self.peer_cert_public_key = self.peer_cert.public_key()

        # verify sig and finish(hmac)
        H = self.hash.copy()
        H.update(self.hello_bytes)
        H.update(self.peer_hello_bytes)
        H.update(self.peer_cert_bytes)
        context_hash = H.finalize()
        self.peer_cert_public_key.verify(
            signature=self.peer_sig, data=context_hash,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256())
        H = self.hash.copy()
        H.update(self.hello_bytes)
        H.update(self.peer_hello_bytes)
        H.update(self.peer_cert_bytes)
        H.update(self.peer_sig)
        context_hash = H.finalize()
        hmac_ = hmac.HMAC(key=self.peer_fk, algorithm=hashes.SHA256())
        hmac_.update(context_hash)
        pf = hmac_.finalize()
        assert pf == peer_finish

    def server_verify_cert(self, peer_cert_bytes, peer_sig, peer_finish):
        self.peer_cert_bytes = peer_cert_bytes
        self.peer_sig = peer_sig
        self.peer_finish = peer_finish

        self.peer_cert = x509.load_pem_x509_certificate(peer_cert_bytes)
        self.peer_cert_public_key = self.peer_cert.public_key()

        # verify sig and finish(hmac)
        H = self.hash.copy()
        H.update(self.peer_hello_bytes)
        H.update(self.hello_bytes)
        H.update(self.peer_cert_bytes)
        context_hash = H.finalize()
        self.peer_cert_public_key.verify(
            signature=self.peer_sig, data=context_hash,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256())
        H = self.hash.copy()
        H.update(self.peer_hello_bytes)
        H.update(self.hello_bytes)
        H.update(self.peer_cert_bytes)
        H.update(self.peer_sig)
        context_hash = H.finalize()
        hmac_ = hmac.HMAC(key=self.peer_fk, algorithm=hashes.SHA256())
        hmac_.update(context_hash)
        pf = hmac_.finalize()
        assert pf == peer_finish
    def client_build_hello(self):
        hello = {}
        self.ec_private_key = x25519.X25519PrivateKey.generate()
        self.ec_public_key = self.ec_private_key.public_key()
        hello['nonce'] = self.nonce
        hello['pub'] = self.ec_public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        self.hello = hello
        hello_bytes = pickle.dumps(hello)
        self.hello_bytes = hello_bytes
        hello_back = pickle.loads(hello_bytes)
        assert hello == hello_back
        # print("client send hello")
        # print(self.hello)
        return hello_bytes


    def server_handle_hello(self, hello_bytes):
        client_hello = pickle.loads(hello_bytes)
        # print("server_handle_hello")
        # print("client_hello = ", client_hello)
        self.peer_ec_public_key = x25519.X25519PublicKey.from_public_bytes(client_hello['pub'])
        self.peer_nonce = client_hello['nonce']

        self.ec_private_key = x25519.X25519PrivateKey.generate()
        self.ec_public_key = self.ec_private_key.public_key()
        self.nonce = os.urandom(32)
        server_hello = {}
        server_hello['nonce'] = self.nonce
        server_hello['pub'] = self.ec_public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        self.hello = server_hello
        # print("server_hello = ", server_hello)
        server_hello_bytes = pickle.dumps(server_hello)
        self.hello_bytes = server_hello_bytes
        self.peer_hello_bytes = hello_bytes

        self.dhe = self.ec_private_key.exchange(self.peer_ec_public_key)
        self.handshake_secret = key_extra(hashes.SHA256(), C1, self.dhe)
        H = self.hash.copy()
        H.update(hello_bytes + server_hello_bytes)
        hash_ch_sh = H.finalize()
        self.handshake_traffic_secret = PRF(
            secret=self.handshake_secret,
            seed=L2 + hash_ch_sh,
            length=32)
        self.peer_handshake_traffic_secret = PRF(
            secret=self.handshake_secret,
            seed=L1 + hash_ch_sh,
            length=32)
        H = self.hash.copy()
        H.update(b'')
        empty_hash = H.finalize()
        self.dhs= PRF(
            secret=self.handshake_secret,
            seed=L3 + empty_hash,
            length=32)

        self.traffic_key= PRF(
            secret=self.handshake_secret,
            seed=L4 + empty_hash,
            length=32)
        self.peer_traffic_key= PRF(
            secret=self.handshake_secret,
            seed=L4 + empty_hash,
            length=32)

        SCert, SSig, SFinish = self.server_send_cert()
        cert_info = {'cert': SCert, 'sig': SSig, 'finish': SFinish}
        cert_info_bytes = pickle.dumps(cert_info)
        encrypted_cert_info = encrypt_data(self.traffic_key, cert_info_bytes)

        return server_hello_bytes, encrypted_cert_info


    def client_handle_hello(self, hello_bytes,encrypted_cert_info):
        server_hello = pickle.loads(hello_bytes)
        # print("client_handle_hello")
        # print(server_hello)
        self.peer_ec_public_key = x25519.X25519PublicKey.from_public_bytes(server_hello['pub'])
        self.peer_nonce = server_hello['nonce']
        self.peer_hello_bytes = hello_bytes

        self.dhe = self.ec_private_key.exchange(self.peer_ec_public_key)
        self.handshake_secret = key_extra(hashes.SHA256(), C1, self.dhe)
        H = self.hash.copy()
        H.update(pickle.dumps(self.hello) + hello_bytes)
        hash_ch_sh = H.finalize()
        self.handshake_traffic_secret= PRF(
            secret=self.handshake_secret,
            seed=L1 + hash_ch_sh,
            length=32)
        self.peer_handshake_traffic_secret= PRF(
            secret=self.handshake_secret,
            seed=L2 + hash_ch_sh,
            length=32)
        H = self.hash.copy()
        H.update(b'')
        empty_hash = H.finalize()
        self.dhs = PRF(
            secret=self.handshake_secret,
            seed=L3 + empty_hash,
            length=32)

        self.traffic_key= PRF(
            secret=self.handshake_secret,
            seed=L4 + empty_hash,
            length=32)
        self.peer_traffic_key= PRF(
            secret=self.handshake_secret,
            seed=L4 + empty_hash,
            length=32)


        decrypted_cert_info_bytes = decrypt_data(self.traffic_key, encrypted_cert_info)
        decrypted_cert_info = pickle.loads(decrypted_cert_info_bytes)
        self.client_verify_cert(
            peer_cert_bytes=decrypted_cert_info['cert'],
            peer_sig=decrypted_cert_info['sig'],
            peer_finish=decrypted_cert_info['finish']
        )
        CCert, CSig, CFinish = self.client_send_cert()
        client_cert_info = {'cert': CCert, 'sig': CSig, 'finish': CFinish}
        client_cert_info_bytes = pickle.dumps(client_cert_info)
        client_encrypted_cert_info = encrypt_data(self.traffic_key, client_cert_info_bytes)
        return client_encrypted_cert_info

    def server_verify_c(self, encrypted_client_cert_info):
        decrypted_client_cert_info_bytes = decrypt_data(self.traffic_key, encrypted_client_cert_info)
        decrypted_client_cert_info = pickle.loads(decrypted_client_cert_info_bytes)
        peer_cert_bytes = decrypted_client_cert_info['cert']
        peer_sig = decrypted_client_cert_info['sig']
        peer_finish = decrypted_client_cert_info['finish']
        self.server_verify_cert(peer_cert_bytes, peer_sig, peer_finish)

    def server_ats(self):
        H = self.hash.copy()
        H.update(self.peer_hello_bytes)
        H.update(self.hello_bytes)
        H.update(self.peer_cert_bytes)
        H.update(self.cert_bytes)
        H.update(self.peer_sig)
        H.update(self.sig)
        H.update(self.peer_finish)
        H.update(self.finish)
        all_context_hash = H.finalize()
        self.master_secret = key_extra(algorithm=hashes.SHA256(), salt=b'0', key_material=self.dhs)
        self.ats= PRF(
            secret=self.handshake_secret,
            seed=L8 + all_context_hash,
            length=32)
        self.peer_ats= PRF(
            secret=self.handshake_secret,
            seed=L9 + all_context_hash,
            length=32)

    def client_ats(self):
        H = self.hash.copy()
        H.update(self.hello_bytes)
        H.update(self.peer_hello_bytes)
        H.update(self.cert_bytes)
        H.update(self.peer_cert_bytes)
        H.update(self.sig)
        H.update(self.peer_sig)
        H.update(self.finish)
        H.update(self.peer_finish)
        all_context_hash = H.finalize()
        self.master_secret = key_extra(algorithm=hashes.SHA256(), salt=b'0', key_material=self.dhs)
        self.ats= PRF(
            secret=self.handshake_secret,
            seed=L9 + all_context_hash,
            length=32)
        self.peer_ats= PRF(
            secret=self.handshake_secret,
            seed=L8 + all_context_hash,
            length=32)