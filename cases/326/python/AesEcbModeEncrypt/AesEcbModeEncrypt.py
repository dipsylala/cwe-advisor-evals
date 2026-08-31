from flask import Flask, request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

app = Flask(__name__)

ENCRYPTION_KEY = b'0123456789abcdef'  # 16-byte AES-128 key


@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    message = request.form['message'].encode('utf-8')

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()

    # SAST FINDING: CWE-326 (Inadequate Encryption Strength) reported here. Sink is the next statement.
    encryptor = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.ECB()).encryptor()

    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return ciphertext.hex()


if __name__ == '__main__':
    app.run()
