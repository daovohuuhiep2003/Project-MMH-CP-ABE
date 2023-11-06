from Include import AC17Serialize as AC17Serialize
from Include import SerializeKey as SerializeKey
from Crypto.Util.number import bytes_to_long,long_to_bytes
import json
import socket
import base64
import signal
import ssl


def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    global sock
    sock.close()
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    # Khởi tạo server socket
    HOST = '0.0.0.0'
    PORT = 8888
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
                    print(f'Connected by {addr}')

                    # Nhận dữ liệu từ client
                    index = conn.recv(1024)
                    print(index)
                    print("Received index!")

                    #Khởi tạo tên filename   
                    attrName = "./Center_Autho/attr" + index.decode('utf-8') + ".txt"
                    mkName = "./Center_Autho/msk" + index.decode('utf-8') + ".pem"
                    pkName = "./Center_Autho/pk" + index.decode('utf-8') + ".pem"

                    #Lấy attribute
                    attr_str = conn.recv(1024)
                    print(attr_str)
                    print("Received attribute!")
                    sourcefile = open(attrName, 'wb')
                    sourcefile.write(attr_str)
                    sourcefile.close()

                    # Đợi phản hồi từ server
                    key = SerializeKey.serializeKey()

                    # receive the first response
                    response = ''
                    while True:
                        data = conn.recv(1024)
                        response += data.decode('utf-8')
                        if len(data) < 1024:
                            break
                    print(response)
                    #Tách bytes 
                    response1 = response[:880]
                    response2 = response[880:]
                    print("Received key!")
                    #Lấy pk
                    pk_bytes = base64.b64decode(response1)
                    pk = key.unjsonify_pk(pk_bytes)
                    #Lấy sk
                    mk_bytes = base64.b64decode(response2)
                    mk = key.unjsonify_mk(mk_bytes)
                    key.save_file_pk(pk, pkName)
                    key.save_file_mk(mk, mkName)
                    print('Finished')

