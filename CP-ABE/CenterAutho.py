import threading
from Include import SerializeAC17 as Serialize
from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from charm.core.engine.util import *
from charm.schemes.abenc.ac17 import AC17CPABE
from charm.toolbox.msp import MSP
from Include import CPABE as cp_abe
from Crypto.Util.number import bytes_to_long,long_to_bytes
import json
import socket
import base64
import ssl


def handle_data_owner_8888(conn, addr):
    try:
        print(f'\n---Connected by data owner---')
        # Nhận dữ liệu từ client
        index = conn.recv(1024)
        print(index)
        print("Received index!")

        #Khởi tạo tên filename   
        mkName = "./Center_Autho/msk" + index.decode('utf-8') + ".pem"
        pkName = "./Center_Autho/pk" + index.decode('utf-8') + ".pem"

        # Đợi phản hồi từ server
        key = Serialize.Serialize()

        # Nhận phản hồi
        response = ''
        while True:
            data = conn.recv(1024)
            response += data.decode('utf-8')
            if len(data) < 1024:
                break

        #Tách public key và master key
        response1 = response[:880]
        response2 = response[880:]
        print("Received key!")
        pk_bytes = base64.b64decode(response1)
        pk = key.unjsonify_pk(pk_bytes)
        mk_bytes = base64.b64decode(response2)
        mk = key.unjsonify_mk(mk_bytes)
        key.save_file_pk(pk, pkName)
        key.save_file_mk(mk, mkName)
        print('Finished')
    except:
        print("ERROR")


def handle_user_62345(conn, addr):
    try:
        print(f'\n---Connected by user---')
        # Nhận dữ liệu từ client (Attr + request)
        json_str = conn.recv(1024)
        json_data = json.loads(json_str)
        print("Received data!")

        #Khởi tạo tên filename   
        mkName = "./Center_Autho/msk" + json_data["request"] + ".pem"
        pkName = "./Center_Autho/pk" + json_data["request"] + ".pem"
                
        #Tiến hành tạo secret key (private key)
        print("Preparing the encryption key...")
        abe = cp_abe.CP_ABE()
        key = Serialize.Serialize()
        attr_list = [json_data['ID'].upper(), json_data["Faculty"].upper()]
        mk = key.load_file_mk(mkName)
        pk = key.load_file_pk(pkName)
        sk = abe.PrivateKeyGen(pk, mk, attr_list)
        sk_bytes = key.jsonify_sk(sk)
        sk_bytes = base64.b64encode(sk_bytes.encode())
        pk_bytes = key.jsonify_pk(pk)
        pk_bytes = base64.b64encode(pk_bytes.encode())

        # Gửi pk+sk
        conn.sendall(pk_bytes+sk_bytes)
        print("Sent the key")
        conn.close()
        print("Connection closed")
    except:
        print("ERROR")

def listen_port(context, port, handle_client):
    # Mở kết nối trên cổng và lắng nghe kết nối
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(('0.0.0.0', port))
        sock.listen(1)
        with context.wrap_socket(sock, server_side=True) as ssock:
            print(f'Server started, listening on port {port}...')
            while True:
                try:
                    # Lắng nghe kết nối từ client
                    conn, addr = ssock.accept()
                    thread = threading.Thread(target=handle_client, args=(conn, addr))
                    thread.start()
                except KeyboardInterrupt:
                    print('\nServer stopped')
                    break
                except:
                    print('Disconnected!')

def start_server():
    try:
        # Khởi tạo kết nối SSL với cert và sk trong folder(local)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('./Center_Autho/server.crt', './Center_Autho/server.key')

        # Tạo 2 thread để lắng nghe kết nối trên 2 port
        thread_8888 = threading.Thread(target=listen_port, args=(context, 8888, handle_data_owner_8888))
        thread_62345 = threading.Thread(target=listen_port, args=(context, 62345, handle_user_62345))

        # Bắt đầu chạy thread
        thread_8888.start()
        thread_62345.start()
    except:
        print("ERROR")

# Khởi chạy server
if __name__ == '__main__':
    start_server()