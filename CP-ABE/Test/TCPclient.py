import socket
import json
import base64
from Include import SerializeKey as SerializeKey
from Include import CPABE as cp_abe

class TCPclient:
    def connect_returnPlt(self, json_data, request, ciphertextName):
        try:
            try:
                # Kết nối đến máy chủ đích
                host = 'localhost'
                port = 62345
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((host, port))
            except:
                print("Connection with the CA is failed")
                exit(1)

            #Tạo dữ liệu và gửi đi
            json_data["request"] = request
            json_str = json.dumps(json_data)
            client_socket.sendall(json_str.encode('utf-8'))

            # Đợi phản hồi từ server
            key = SerializeKey.serializeKey()

            # receive the first response
            response = ''
            while True:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    response += data.decode('utf-8')
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

            #Giả mã
            print('Decrypting file...')
            abe = cp_abe.CP_ABE()
            plt = abe.ABEdecryption(ciphertextName, pk, sk)
            return plt
        except:
            print("ERROR")
            return None
