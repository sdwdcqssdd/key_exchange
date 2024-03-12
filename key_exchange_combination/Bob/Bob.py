import hashlib
import cryptography
import hashlib
import socket
import hmac as hc
from mqv import mqv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from tls import *

class Bob:
    def __init__(self,protocal):
        self.protocal = protocal
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        server_address = ('localhost', 9999)
        self.sock.connect(server_address)

    def key_exchange(self):
        if self.protocal == '3DH':

            with open("parameters",'rb') as f:
                parameters_bytes = f.read()

            parameters = serialization.load_pem_parameters(parameters_bytes,dh.DHParameters)
            print("g:" + str(parameters.parameter_numbers().g))
            print("p:" + str(parameters.parameter_numbers().p))
            print()

            with open("private_key_b",'rb') as f:
                b_bytes = f.read()

            private_key_b = serialization.load_pem_private_key(
                b_bytes,
                password=None
            )
            print("长期私钥为："+str(private_key_b.private_numbers().x))
            print()
            public_key_B = private_key_b.public_key()
            print("长期公钥为："+str(public_key_B.public_numbers().y))
            print()
            A_bytes = self.sock.recv(1024)
            public_key_A = serialization.load_pem_public_key(A_bytes)
            print("Alice长期公钥为："+str(public_key_A.public_numbers().y))
            print()
            B_bytes = public_key_B.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            self.sock.sendall(B_bytes)

            X_bytes = self.sock.recv(1024)
            public_key_X = serialization.load_pem_public_key(X_bytes)
            print("Alice临时公钥为："+str(public_key_X.public_numbers().y))
            print()
            private_key_y = parameters.generate_private_key()
            print("临时私钥为："+str(private_key_y.private_numbers().x))
            print()
            public_key_Y = private_key_y.public_key()
            print("临时公钥为："+str(public_key_Y.public_numbers().y))
            print()
            Y_bytes = public_key_Y.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            self.sock.sendall(Y_bytes)

            Ay = private_key_y.exchange(public_key_A)
            print("A^y字节数组为：",end='')
            print(Ay)
            print()
            Xy = private_key_y.exchange(public_key_X)
            print("X^y字节数组为：",end='')
            print(Xy)
            print()
            Xb = private_key_b.exchange(public_key_X)
            print("X^b字节数组为：",end='')
            print(Xb)
            print()
            shared_key = Ay + Xy + Xb
            derived_key = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=None,
                info=None
            ).derive(shared_key)

            print("派生密钥为：",end='')
            print(derived_key) 
            self.sock.close()
        elif self.protocal == 'MQV':

            with open("parameters",'rb') as f:
                parameters_bytes = f.read()
                

            parameters = serialization.load_pem_parameters(parameters_bytes,dh.DHParameters)
            print("g:" + str(parameters.parameter_numbers().g))
            print("p:" + str(parameters.parameter_numbers().p))
            print()
            with open("private_key_b",'rb') as f:
                client_private_key_bytes = f.read()

            client_private_key = serialization.load_pem_private_key(
                client_private_key_bytes,
                password=None
            )
            print("长期私钥为："+str(client_private_key.private_numbers().x))
            print()
            client_public_key = client_private_key.public_key()
            print("长期公钥为："+str(client_public_key.public_numbers().y))
            print()

            other_public_key_bytes = self.sock.recv(1024)
            other_public_key = serialization.load_pem_public_key(other_public_key_bytes)
            print("Alice长期公钥为："+str(other_public_key.public_numbers().y))
            print()

            client_ephemeral_private_key = parameters.generate_private_key()
            print("临时私钥为："+str(client_ephemeral_private_key.private_numbers().x))
            print()
            client_ephemeral_public_key = client_ephemeral_private_key.public_key()
            print("临时公钥为："+str(client_ephemeral_public_key.public_numbers().y))
            print()
            client_ephemeral_public_key_bytes = client_ephemeral_public_key.public_bytes(encoding=Encoding.PEM,format=PublicFormat.SubjectPublicKeyInfo)
            self.sock.sendall(client_ephemeral_public_key_bytes)

            other_ephemeral_public_key_bytes = self.sock.recv(1024)
            other_ephemeral_public_key = serialization.load_pem_public_key(other_ephemeral_public_key_bytes)
            print("Alice临时公钥为："+str(other_ephemeral_public_key.public_numbers().y))
            print()
            
            client_public_key_bytes = client_public_key.public_bytes(encoding=Encoding.PEM,format=PublicFormat.SubjectPublicKeyInfo)
            self.sock.sendall(client_public_key_bytes)

            MQV = mqv()

            sigma = MQV.compute_share_key(parameters=parameters,my_ephemeral_priv=client_ephemeral_private_key,my_identity_priv=client_private_key,other_ephemeral_pub=other_ephemeral_public_key,other_identity_pub=other_public_key)
            self.sock.close()


        elif self.protocal == 'SIGMA':
            
            with open("parameters",'rb') as f:
                parameters_bytes = f.read()

            parameters = serialization.load_pem_parameters(parameters_bytes,dh.DHParameters)
            
            
            print("g:" + str(parameters.parameter_numbers().g))
            print("p:" + str(parameters.parameter_numbers().p))
            print()

            y = parameters.generate_private_key()
            print("用于dh交换私钥为："+str(y.private_numbers().x))
            print()
            Y = y.public_key()
            print("用于dh交换公钥为："+str(Y.public_numbers().y))
            print()
            Y_bytes = Y.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            
            X_bytes = self.sock.recv(1024)
            X = serialization.load_pem_public_key(X_bytes)
            print("对方用于dh交换公钥为："+str(X.public_numbers().y))
            print()

            self.sock.sendall(Y_bytes)
 
            self.sock.recv(1024)
           
            bobinfo = b'bob'
            Bob_private_K = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            )
            Bob_public_K = Bob_private_K.public_key()
            print("用于认证的公钥： n:"+str(Bob_public_K.public_numbers().n)+" e:"+str(Bob_public_K.public_numbers().e))
            print()
            kB_bytes = Bob_public_K.public_bytes(encoding=Encoding.PEM,format=PublicFormat.SubjectPublicKeyInfo)

            CA_bob = hashlib.md5(bobinfo+kB_bytes).digest()
            print("发送的证书为：",end='')
            print(CA_bob)
            print()
            
            self.sock.sendall(CA_bob)

            self.sock.recv(1024)
            self.sock.sendall(kB_bytes)
        
            self.sock.recv(1024)

            sign_bob = Bob_private_K.sign(
                X_bytes+Y_bytes,
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("发送的SIGn为：",end='')
            print(sign_bob)
            print()

            self.sock.sendall(sign_bob)

            self.sock.recv(1024)

            km = y.exchange(X)
            print("dh交换得到密钥为：",end='')
            print(km)
            print()
            mac = hc.new(km,CA_bob,hashlib.sha256).digest()
            print("发送的MAc为：",end='')
            print(mac)
            print()
            self.sock.sendall(mac)

            if(self.sock.recv(1024) == b'ok'):
                print("验证成功")
                print()
                self.sock.sendall(b'ok')
            else:
                print("验证失败")   
                print()
                self.sock.sendall(b'ok')
                self.sock.close()
                



            kA_bytes = self.sock.recv(1024)
            self.sock.sendall(b'ok')

            kA = serialization.load_pem_public_key(kA_bytes)
            print("对方用于认证的公钥： n:"+str(kA.public_numbers().n)+" e:"+str(kA.public_numbers().e))
            print()

            CA_alice = self.sock.recv(1024)
            self.sock.sendall(b'ok')

            print("接收的证书为：",end='')
            print(CA_alice)
            print()
            
     
            sign_alice = self.sock.recv(1024)
            self.sock.sendall(b'ok')
            print("接收的SIGn为：",end='')
            print(sign_alice)
            print()
            
            mac_alice = self.sock.recv(1024)
            self.sock.sendall(b'ok')
            print("接收的MAc为：",end='')
            print(mac_alice)
            print()

            mac = hc.new(km,CA_alice,hashlib.sha256).digest()
            verify = True
            if(mac==mac_alice):
                print("MAc验证成功")
                print()
                
                
            else:
                print("MAc验证失败")
                print()
                verify = False 

            try:
                kA.verify(
                sign_alice,
                X_bytes + Y_bytes,
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            except cryptography.exceptions.InvalidSignature as e:
                print('SIGn验证失败')
                print()
                verify = False
            else:
                print('SIGn验证成功')  
                print() 
                
            self.sock.recv(1024)
            if(verify == False):
                self.sock.sendall(b'err')
                self.sock.close()
            else:
                self.sock.sendall(b'ok')  


            derived_key = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=None,
                info=None
            ).derive(km)
            print("派生密钥为：",end='')
            print(derived_key)

        elif self.protocal == 'tls':
            with open('./client_cert.pem', 'rb') as file:
                client_cert_bytes = file.read()
            
            with open('./client_private_key.pem', 'rb') as file:
                client_private_bytes = file.read()
            client_private_key = serialization.load_pem_private_key(client_private_bytes, password=None)
            
            client_contex = Context(is_client=True, cert_bytes=client_cert_bytes, priv_bytes=client_private_bytes)

            client_hello_bytes = client_contex.client_build_hello()
            print('client hello 消息：',end='')
            print(client_hello_bytes)
            print()
            self.sock.sendall(client_hello_bytes)
            
            server_hello_bytes = self.sock.recv(1024)
            self.sock.sendall(b'ok')
            encrypted_cert_info = self.sock.recv(1024)

            print('server hello 消息：',end='')
            print(server_hello_bytes)
            print('server加密证书信息：',end='')
            print(encrypted_cert_info)
            print()

            client_encrypted_cert_info = client_contex.client_handle_hello(server_hello_bytes, encrypted_cert_info)
            self.sock.sendall(client_encrypted_cert_info)

            print('client加密证书信息：',end='')
            print(client_encrypted_cert_info)
            print()

            print('dhe:',end='')
            print(client_contex.dhe)
            print('secret handshake: ',end='')
            print(client_contex.handshake_secret)
            print('dhs:',end='')
            print(client_contex.dhs)
            print('peer handshake:',end='')
            print(client_contex.peer_handshake_traffic_secret)
            print('secret traffic handshake:',end='')
            print(client_contex.handshake_traffic_secret)
            print('peer traffic key:',end='')
            print(client_contex.peer_traffic_key)
            print('trafic key:',end='')
            print(client_contex.traffic_key)
            print()

            client_contex.client_ats()
            print('ats:',end='')
            print(client_contex.ats)
            print('peer ats:',end='')
            print(client_contex.peer_ats) 



        self.sock.close()



if __name__ == "__main__":
    protocal = input("交换协议为：")
    client = Bob(protocal)
    client.connect()
    client.key_exchange()
            
               


