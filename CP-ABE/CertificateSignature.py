from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import openssl
from cryptography.x509.oid import NameOID
from OpenSSL import crypto

class signature:
    def Self_signed_certificate(self):
        # Tạo một cặp khóa ECC với đường cong prime256v1
        ec_key = ec.generate_private_key(ec.SECP256R1(), openssl.backend)

        # Chuyển đổi khóa ECC sang định dạng OpenSSL
        key = crypto.PKey.from_cryptography_key(ec_key)

        # Tạo chứng chỉ x509 tự ký
        cert = crypto.X509()
        cert.get_subject().CN = '127.0.0.1'
        cert.get_subject().countryName = 'VN'
        cert.get_subject().O = 'UIT'
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')

        # Giả định phân phát cert cho user và phân phối cert và key cho Center Autho
        with open("./Center_Autho/server.key", "wb") as key_file:
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            
        with open("./Center_Autho/server.crt", "wb") as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        with open("server.crt", "wb") as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def main():
    CA = signature()
    CA.Self_signed_certificate()
    
if __name__ == '__main__':
    main()