import time
import sympy
import random
import hashlib
import cryptography
import hashlib
import base64
import gmpy2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


class mqv:

    def get_p_and_q_bits_half(self,parameters):
        parameter_numbers = parameters.parameter_numbers()
        q = (parameter_numbers.p - 1) // 2
        bit_len = gmpy2.bit_length(q)
        return parameter_numbers.p, bit_len // 2


    def get_d_e(self,X : dh.DHPublicKey, Y: dh.DHPublicKey, l):
        X_numbers = X.public_numbers()
        X_value = X_numbers.y
        Y_numbers = Y.public_numbers()
        Y_value = Y_numbers.y
        
        _2_l = 2 ** l
        
        X_mod = gmpy2.t_mod_2exp(X_value, l)
        d = gmpy2.add(_2_l, X_mod)
        
        Y_mod = gmpy2.t_mod_2exp(Y_value, l)
        e = gmpy2.add(_2_l, Y_mod)
        return d, e


    def compute_share_key(self,parameters: dh.DHParameters, my_ephemeral_priv: dh.DHPrivateKey, my_identity_priv: dh.DHPrivateKey, other_ephemeral_pub: dh.DHPublicKey, other_identity_pub: dh.DHPublicKey):
        p, l = self.get_p_and_q_bits_half(parameters)
        d, e = self.get_d_e(my_ephemeral_priv.public_key(), other_ephemeral_pub, l)
        
        my_ephemeral_priv_value = my_ephemeral_priv.private_numbers().x
        my_identity_priv_value = my_identity_priv.private_numbers().x
        other_ephemeral_pub_value = other_ephemeral_pub.public_numbers().y
        other_identity_pub_value = other_identity_pub.public_numbers().y
        
        sigma = gmpy2.powmod(other_identity_pub_value, e, p)
        sigma = gmpy2.mul(other_ephemeral_pub_value, sigma)
        sigma = gmpy2.f_mod(sigma, p)
        sigma = gmpy2.powmod(sigma, gmpy2.add(my_ephemeral_priv_value, gmpy2.mul(d, my_identity_priv_value)), p)
        
        sigma = int(sigma)
        
        # digest = hashes.Hash(hashes.SHA512())
        # digest.update(sigma.to_bytes(length=64, byteorder='little'))
        # sigma = digest.finalize()
        
        digest = hashlib.sha512()
        digest.update(sigma.to_bytes(length=64, byteorder='little'))
        sigma = digest.hexdigest()
        print("共享密钥为："+sigma)
        sigma = int(sigma, 16)
        
        return sigma







