from . import CPABE as cp_abe
from . import SerializeAC17 as Serialize
from Crypto.Util.number import bytes_to_long,long_to_bytes
from google.cloud import firestore
from google.oauth2 import service_account
import json
import socket
import base64
import ssl


class DataOwner:
    key_path = "./Include/Cloud.json"
    creds = service_account.Credentials.from_service_account_file(key_path)
    db = firestore.Client(credentials=creds)

    def Retrieve_cipher(self, filename):
        doc_ref = self.db.collection(u'Ciphertext').document(filename)
        doc = doc_ref.get()
        # Lấy nội dung của tệp từ document
        try:
            file_content = doc.to_dict()['Data']
            cipherfile = open(filename, 'wb')
            cipherfile.write(file_content)
            cipherfile.close()
            print("Download encryption successful!")
        except:
            print("Download encryption Failed!")
            exit(1)

    def DataOwner_options(self):
        try:
            print("Please select an option:")
            print("1. Add new PHR")
            print("2. Quit")

            choice = input("Enter your choice: ")
            if choice == "1":
                print("You chose to add a new PHR.")
                # Kết nối đến máy chủ đích
                HOST = 'localhost'
                PORT = 8888
                context = ssl.create_default_context()
                context.check_hostname = False
                context.load_verify_locations('server.crt')

                with socket.create_connection((HOST, PORT)) as sock:
                    with context.wrap_socket(sock, server_hostname=HOST) as owner_socket:

                        #Nhập tên file và lấy index
                        fileName = input("Enter name of PHR file (in JSON format): ")
                        if not fileName.endswith('.json'):
                            print("Invalid input file")
                            exit(1)
                        collection_ref = self.db.collection('Ciphertext')
                        docs = collection_ref.get()
                        count = len(docs)
                        index = "" + str(count+1)
                        owner_socket.sendall(index.encode('utf-8'))

                        #Đọc file
                        sourcefile = open(fileName, 'rb')
                        msg = sourcefile.read()
                        sourcefile.close()
                        msg_dict = json.loads(msg)

                        #Lấy thuộc tính và policy
                        policy = '((' + msg_dict["ID"] + ') or (' 
                        for item in msg_dict['NGUOIPHUTRACH']:
                            if msg_dict['NGUOIPHUTRACH'][-1] != item:
                                policy += "(" + item['ID'] + ' and ' + item['khoa'].upper() + ")" + " or "
                            else:
                                policy += "(" + item['ID'] + ' and ' + item['khoa'].upper() + ")" + '))'

                        #Chuẩn bị gửi khóa đến Center Authority
                        print("Sent to server....")

                        #Tạo pk, msk và ciphertext
                        abe = cp_abe.CP_ABE()
                        key = Serialize.Serialize()
                        pk, mk = abe.KeyGen()
                        cipher = abe.ABEencryption(fileName, pk, policy)
                        
                        #Gửi pk và msk đến Center Autho
                        pk_bytes = key.jsonify_pk(pk)
                        pk_bytes = base64.b64encode(pk_bytes.encode())
                        mk_bytes = key.jsonify_mk(mk)
                        mk_bytes = base64.b64encode(mk_bytes.encode())
                        owner_socket.sendall(pk_bytes+mk_bytes)
                        
                        #Gửi ciphertext lên cloud
                        cipherName = 'phr'+ index +'.json.crypt'
                        doc_ref = self.db.collection(u'Ciphertext').document(cipherName)
                        doc_ref.set({
                            u'Data': cipher
                        })
                        print("Add successfully!")
                        owner_socket.close()
                        return True

            elif choice == "2":
                print("Goodbye!")
                return True
            else:
                print("Invalid choice. Please try again.")
        except:
            print("ERROR")
            exit(1)