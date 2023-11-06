from Include import firebaseauth as firebase
from Include import TLSclient as TLS
import pyfiglet
import json
import os


def main():
    try:
        banner = pyfiglet.figlet_format("Hospital Database")
        print(banner)

        # Xác thực database chứa thông tin login của user
        auth = firebase.firebaseauth() 
        try:
            # Xác thực người dùng
            email, password = auth.login()
        except:
            print("Good bye!")
            return
        
        # User yêu cầu bản PHR tương ứng
        request = input("Enter the PHR ID (integer):")
        try:
            int(request)
        except ValueError:
            print("Invalid input")
            return
        
        #Tải ciphertext từ cloud
        ciphertextName = "phr" + request + ".json.crypt"
        print('Retrieving encrypted file...')
        auth.Retrieve_cipher(ciphertextName)

        #Kết nối với Certral Authority và tiến hành giải mã
        print('Connecting to Central Auth Server...')
        connect = TLS.client()
        plt = connect.connect_returnPlt(auth.authenticate_user(email, password), request, ciphertextName)
        os.system("rm " + ciphertextName)
        
        if plt:    
            #Ghi nội dung JSON vào file
            json_str = plt.decode('utf-8')
            with open('data_decrypt.json', 'w') as json_file:
                json.dump(json.loads(json_str), json_file, indent=4)
            print("The plaintext has been exported to the file data_decrypt.json")
        else:
            exit(1)
    except KeyboardInterrupt:
        print('\nUser stopped')
        exit(1)
    except:
        print("You do not have access")
        exit(1)
    
if __name__=="__main__":
    main()