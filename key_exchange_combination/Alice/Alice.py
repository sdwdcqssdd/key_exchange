import hashlib
import cryptography
import hashlib
import socket
import hmac as hc
import time
from mqv import mqv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from tls import *

class Alice:
    def __init__(self,protocal):
        self.protocal = protocal
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', 9999)
        self.sock.bind(server_address)
        self.sock.listen(2)
        self.receiver_connection = None
        self.receiver_address = None
        self.startTime = None
        self.endTime = None

    def connect(self):
        print('等待Bob连接...')
        self.receiver_connection,self.receiver_address = self.sock.accept()
        print('Bob已连接')
        self.startTime = time.time()
   

    def key_exchange(self):
        if self.protocal == '3DH':

            with open("parameters",'rb') as f:
                parameters_bytes = f.read()

            parameters = serialization.load_pem_parameters(parameters_bytes,dh.DHParameters)
            print("g:" + str(parameters.parameter_numbers().g))
            print("p:" + str(parameters.parameter_numbers().p))
            print()
            with open("private_key_a",'rb') as f:
                a_bytes = f.read()

            private_key_a = serialization.load_pem_private_key(
                a_bytes,
                password=None
            )

            print("长期私钥为："+str(private_key_a.private_numbers().x))
            print()
            public_key_A = private_key_a.public_key()
            print("长期公钥为："+str(public_key_A.public_numbers().y))
            print()
            A_bytes = public_key_A.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            self.receiver_connection.sendall(A_bytes)

            B_bytes = self.receiver_connection.recv(1024)
            public_key_B = serialization.load_pem_public_key(B_bytes)
            print("Bob长期公钥为："+str(public_key_B.public_numbers().y))
            print()
            private_key_x = parameters.generate_private_key()
            print("临时私钥为："+str(private_key_x.private_numbers().x))
            print()
            public_key_X = private_key_x.public_key()
            print("临时公钥为："+str(public_key_X.public_numbers().y))
            print()
            X_bytes = public_key_X.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            self.receiver_connection.sendall(X_bytes)

            Y_bytes = self.receiver_connection.recv(1024)
            public_key_Y = serialization.load_pem_public_key(Y_bytes)
            print("Bob临时公钥为："+str(public_key_Y.public_numbers().y))
            print()
            Ya = private_key_a.exchange(public_key_Y)
            print("Y^a字节数组为：",end='')
            print(Ya)
            print()
            Yx = private_key_x.exchange(public_key_Y)
            print("Y^x字节数组为：",end='')
            print(Yx)
            print()
            Bx = private_key_x.exchange(public_key_B)
            print("B^x字节数组为：",end='')
            print(Bx)
            print()
            shared_key = Ya + Yx + Bx
            derived_key = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=None,
                info=None
            ).derive(shared_key)
            print("派生密钥为：",end='')
            print(derived_key)

            self.receiver_connection.close()
            
        elif self.protocal == 'MQV':

            with open("parameters",'rb') as f:
                parameters_bytes = f.read()

            parameters = serialization.load_pem_parameters(parameters_bytes,dh.DHParameters)
            print("g:" + str(parameters.parameter_numbers().g))
            print("p:" + str(parameters.parameter_numbers().p))
            print()
            with open("private_key_a",'rb') as f:
                server_private_key_bytes = f.read()

            server_private_key = serialization.load_pem_private_key(
                server_private_key_bytes,
                password=None
            )
            print("长期私钥为："+str(server_private_key.private_numbers().x))
            print()
            server_public_key = server_private_key.public_key()
            print("长期公钥为："+str(server_public_key.public_numbers().y))
            print()
            server_public_key_bytes = server_public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
            self.receiver_connection.sendall(server_public_key_bytes)

            other_ephemeral_public_key_bytes = self.receiver_connection.recv(1024)
            other_ephemeral_public_key = load_pem_public_key(other_ephemeral_public_key_bytes)
            print("Bob临时公钥为："+str(other_ephemeral_public_key.public_numbers().y))
            print()
            server_ephemeral_private_key = parameters.generate_private_key()
            print("临时私钥为："+str(server_ephemeral_private_key.private_numbers().x))
            print()
            server_ephemeral_public_key = server_ephemeral_private_key.public_key()
            server_ephemeral_public_key_bytes = server_ephemeral_public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
            print("临时公钥为："+str(server_ephemeral_public_key.public_numbers().y))
            print()
            self.receiver_connection.sendall(server_ephemeral_public_key_bytes)

            other_public_key_bytes = self.receiver_connection.recv(1024)
            other_public_key = load_pem_public_key(other_public_key_bytes)
            print("Bob长期公钥为："+str(other_public_key.public_numbers().y))
            print()
            
            MQV = mqv()
            sigma = MQV.compute_share_key(parameters=parameters,my_ephemeral_priv=server_ephemeral_private_key,my_identity_priv=server_private_key,other_ephemeral_pub=other_ephemeral_public_key,other_identity_pub=other_public_key)
            
            self.receiver_connection.close()

        elif self.protocal == 'SIGMA':
            
            with open("parameters",'rb') as f:
                parameters_bytes = f.read()

            parameters = serialization.load_pem_parameters(parameters_bytes,dh.DHParameters)
            print("g:" + str(parameters.parameter_numbers().g))
            print("p:" + str(parameters.parameter_numbers().p))
            print()
            

            x = parameters.generate_private_key()
            print("用于dh交换私钥为："+str(x.private_numbers().x))
            print()
            X = x.public_key()
            print("用于dh交换公钥为："+str(X.public_numbers().y))
            print()
            X_bytes = X.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            self.receiver_connection.sendall(X_bytes)

            Y_bytes = self.receiver_connection.recv(1024)
            Y = serialization.load_pem_public_key(Y_bytes)
            print("对方用于dh交换公钥为："+str(Y.public_numbers().y))
            print()
            self.receiver_connection.sendall(b'ok')
           
            CA_bob = self.receiver_connection.recv(1024)
            print("接收的证书为：",end='')
            print(CA_bob)
            print()

            self.receiver_connection.sendall(b'ok')

            kB_bytes = self.receiver_connection.recv(1024)

            kB = serialization.load_pem_public_key(kB_bytes)
            print("对方用于认证的公钥： n:"+str(kB.public_numbers().n)+" e:"+str(kB.public_numbers().e))
            print()
            self.receiver_connection.sendall(b'ok')

            sign_bob = self.receiver_connection.recv(1024)

            self.receiver_connection.sendall(b'ok')

            print("接收的SIGn为：",end='')
            print(sign_bob)
            print()

            mac_bob = self.receiver_connection.recv(1024)

            km = x.exchange(Y)
            print("dh交换得到密钥为：",end='')
            print(km)
            print()

            mac = hc.new(km,CA_bob,hashlib.sha256).digest()
            print("接收的MAc为：",end='')
            print(mac_bob)
            print()

            
            verify = True
            if(mac==mac_bob):
                print("MAc验证成功")
                print()
            else:
                print("MAc验证失败")   
                print()
                verify = False
            try:
                kB.verify(
                sign_bob,
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
                
            if(verify == False):
                self.receiver_connection.sendall(b'err')
                self.receiver_connection.close()
            else:
                self.receiver_connection.sendall(b'ok')    


            self.receiver_connection.recv(1024)
            aliceinfo = b'alice'
            Alice_private_K = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            )
            Alice_public_K = Alice_private_K.public_key()
            print("用于认证的公钥： n:"+str(Alice_public_K.public_numbers().n)+" e:"+str(Alice_public_K.public_numbers().e))
            Alice_public_K_bytes = Alice_public_K.public_bytes(serialization.Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
            CA_alice = hashlib.md5(aliceinfo+Alice_public_K_bytes).digest()

            self.receiver_connection.sendall(Alice_public_K_bytes)
            self.receiver_connection.recv(1024)

            print("发送的证书为：",end='')
            print(CA_alice)
            print()
            self.receiver_connection.sendall(CA_alice)
            self.receiver_connection.recv(1024)
            
            sign_alice = Alice_private_K.sign(
                X_bytes+Y_bytes,
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print("发送的SIGn为：",end='')
            print(sign_alice)
            print()
            self.receiver_connection.sendall(sign_alice)
            self.receiver_connection.recv(1024)
            mac = hc.new(km,CA_alice,hashlib.sha256).digest()
            print("发送的MAc为：",end='')
            print(mac)
            print()
            self.receiver_connection.sendall(mac)
            self.receiver_connection.recv(1024)

            self.receiver_connection.sendall(b'excuse')
            if self.receiver_connection.recv(1024) == b'ok':
                print("验证成功")
                print()
                
            else:
                print("验证失败")   
                print()
                self.receiver_connection.close()
            derived_key = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=None,
                info=None
            ).derive(km)
            print("派生密钥为：",end='')
            print(derived_key)

        elif self.protocal == 'tls':
            server_cert_bytes = None
            with open('./server_cert.pem', 'rb') as file:
                server_cert_bytes = file.read()
            
            server_private_bytes = None
            with open('./server_private_key.pem', 'rb') as file:
                server_private_bytes = file.read()
            server_private_key = serialization.load_pem_private_key(server_private_bytes, password=None)
            
            server_contex = Context(is_client=False, cert_bytes=server_cert_bytes, priv_bytes=server_private_bytes)

            client_hello_bytes = self.receiver_connection.recv(1024)
            print('client hello 消息：',end='')
            print(client_hello_bytes)
            print()

            server_hello_bytes, encrypted_cert_info = server_contex.server_handle_hello(client_hello_bytes)
            print('server hello 消息：',end='')
            print(server_hello_bytes)
            print('server加密证书信息：',end='')
            print(encrypted_cert_info)
            print()
            
            self.receiver_connection.sendall(server_hello_bytes)
            self.receiver_connection.recv(1024)
            self.receiver_connection.sendall(encrypted_cert_info)
            client_encrypted_cert_info = self.receiver_connection.recv(1024)

            print('client加密证书信息：',end='')
            print(client_encrypted_cert_info)
            print()

            server_contex.server_verify_c(client_encrypted_cert_info)

            print('dhe:',end='')
            print(server_contex.dhe)
            print('secret handshake: ',end='')
            print(server_contex.handshake_secret)
            print('dhs:',end='')
            print(server_contex.dhs)
            print('peer handshake:',end='')
            print(server_contex.peer_handshake_traffic_secret)
            print('secret traffic handshake:',end='')
            print(server_contex.handshake_traffic_secret)
            print('peer traffic key:',end='')
            print(server_contex.peer_traffic_key)
            print('trafic key:',end='')
            print(server_contex.traffic_key)
            print()

            server_contex.server_ats()
            print('ats:',end='')
            print(server_contex.ats)
            print('peer ats:',end='')
            print(server_contex.peer_ats)
            
        self.endTime = time.time()
        self.receiver_connection.close()
        print('耗时：',end='')
        print(self.endTime - self.startTime)    


if __name__ == "__main__":

    protocal = input("交换协议为：")
    server = Alice(protocal)
    server.connect()
    server.key_exchange()
    