from . import SerializeAC17 as Serialize
from . import CPABE as cp_abe
import socket
import ssl
import json
import base64

class client:
    # Khởi tạo kết nối ssl giữa người dùng và CA
    def connect_returnPlt(self, json_data, request, ciphertextName):
        try:
            HOST = '127.0.0.1'
            PORT =62345
            context = ssl.create_default_context()
            context.check_hostname = False
            context.load_verify_locations('server.crt')

            #Thiết lập kết nối
            with socket.create_connection((HOST, PORT)) as sock:
                with context.wrap_socket(sock, server_hostname=HOST) as client_socket:
                    #Tạo dữ liệu và gửi đi
                    json_data["request"] = request
                    json_str = json.dumps(json_data)
                    client_socket.sendall(json_str.encode('utf-8'))
                    key = Serialize.Serialize()

                    # Nhận phản hồi
                    response = ''
                    while True:
                        try:
                            data = client_socket.recv(1024)
                            response += data.decode('utf-8')
                            if len(data) < 1024:
                                break
                        except socket.timeout:
                            print('Timeout occurred')
                            break
                    
                    #Tách bytes 
                    response1 = response[:880]
                    response2 = response[880:]

                    #Lấy pk
                    pk_bytes = base64.b64decode(response1)
                    pk = key.unjsonify_pk(pk_bytes)

                    #Lấy sk
                    sk_bytes = base64.b64decode(response2)
                    sk = key.unjsonify_sk(sk_bytes)

                    # Đóng kết nối
                    client_socket.close()

                    #Giải mã
                    print('Decrypting file...')
                    abe = cp_abe.CP_ABE()
                    plt = abe.ABEdecryption(ciphertextName, pk, sk)
                    return plt
        except:
            print("ERROR")
            return None