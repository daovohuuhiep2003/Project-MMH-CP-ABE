import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
import json

# Tạo credentials object từ file json chứa thông tin xác thực
cred = credentials.Certificate('info-7110d-firebase-adminsdk-v1or8-9216d6e154.json')

# Khởi tạo ứng dụng Firebase
firebase_admin.initialize_app(cred)

# Lấy tham chiếu tới database
db = firestore.client()

sourcefile = open("phr.json.txt", 'r')  # Mở file với chế độ 'r'
data = sourcefile.read().decode('utf-16')
sourcefile.close()

json_data = json.loads(data)  # Chuyển đổi chuỗi thành một dictionary

# Thêm dữ liệu vào collection "Ciphertext"
doc_ref = db.collection('Ciphertext').document()
doc_ref.set(json_data)

