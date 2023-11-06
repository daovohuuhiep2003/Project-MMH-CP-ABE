from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from charm.core.engine.util import *
from charm.schemes.abenc.ac17 import AC17CPABE
from charm.toolbox.msp import MSP
from Include import AC17Serialize as AC17Serialize
from Include import CPABE as cp_abe
from Include import SerializeKey as SerializeKey
from Crypto.Util.number import bytes_to_long,long_to_bytes
import json
import socket
import base64
import ssl
import signal

def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    global sock
    sock.close()
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    HOST = '0.0.0.0'
    PORT = 62345
    #Mở kết nối SSL với cert và sk trong folder(local)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('./Center_Autho/server.crt', './Center_Autho/server.key')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)
        with context.wrap_socket(sock, server_side=True) as ssock:
            print('Server started, listening...')
            while True:
                conn, addr = ssock.accept()
                with conn:
                    print('Connected by', addr)
                    # Nhận dữ liệu từ client (Attr + request)
                    json_str = conn.recv(1024)
                    json_data = json.loads(json_str)
                    print("Received data!")

                    #Khởi tạo tên filename   
                    attrName = "./Center_Autho/attr" + json_data["request"] + ".txt"
                    mkName = "./Center_Autho/msk" + json_data["request"] + ".pem"
                    pkName = "./Center_Autho/pk" + json_data["request"] + ".pem"

                    #Đọc attr tương ứng với request
                    with open(attrName, 'r') as file:
                        server_data = json.load(file)
                    
                    #Kiểm tra quyền truy cập
                    if json_data['ID'] in server_data and json_data["Faculty"].upper() in server_data:
                        print("Authentication successful")
                        
                        #Tiến hành tạo sk
                        print("Preparing the encryption key...")
                        abe = cp_abe.CP_ABE()
                        key = SerializeKey.serializeKey()
                        attr_list = [json_data['ID'].upper(), json_data["Faculty"].upper()]
                        mk = key.load_file_mk(mkName)
                        pk = key.load_file_pk(pkName)
                        sk = abe.PrivateKeyGen(pk, mk, attr_list)
                        sk_bytes = key.jsonify_sk(sk)
                        sk_bytes = base64.b64encode(sk_bytes.encode())
                        pk_bytes = key.jsonify_pk(pk)
                        pk_bytes = base64.b64encode(pk_bytes.encode())

                        #Gửi pk+sk
                        conn.sendall(pk_bytes+sk_bytes)
                        print("Sent the key")
                        conn.close()
                        print("Connection closed")
                    else:
                        #Dữ liệu không khớp
                        print('Data does not match')
                        conn.close()
                        print("Connection closed")