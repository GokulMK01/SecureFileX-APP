# from flask import Flask, render_template, request
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# import base64

# app = Flask(__name__)

# KEY_SIZE = 16  # AES-128 (change to 24 for AES-192 or 32 for AES-256)

# def pad(data):
#     block_size = AES.block_size
#     return data + (block_size - len(data) % block_size) * b'\0'

# def encrypt(message, key):
#     cipher = AES.new(key, AES.MODE_CBC)
#     ciphertext = cipher.encrypt(pad(message.encode()))
#     return base64.b64encode(cipher.iv + ciphertext).decode()

# def decrypt(ciphertext, key):
#     data = base64.b64decode(ciphertext.encode())
#     iv = data[:AES.block_size]
#     ciphertext = data[AES.block_size:]
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     decrypted_message = cipher.decrypt(ciphertext).rstrip(b'\0').decode()
#     return decrypted_message

# @app.route('/', methods=['GET', 'POST'])
# def index():
#     if request.method == 'POST':
#         choice = request.form['choice']
#         key = request.form['key'].encode()
#         message = request.form['message']

#         if len(key) != KEY_SIZE:
#             return "Invalid key length. Key must be {} bytes long.".format(KEY_SIZE)

#         if choice == 'encrypt':
#             encrypted_message = encrypt(message, key)
#             return render_template('index1.html', result=encrypted_message)
#         elif choice == 'decrypt':
#             decrypted_message = decrypt(message, key)
#             return render_template('index1.html', result=decrypted_message)

#     return render_template('index1.html', result=None)

# if __name__ == '__main__':
#     app.run(debug=True)
from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)

KEY_SIZE = 32 # AES-128 (change to 24 for AES-192 or 32 for AES-256)

def pad(data):
    block_size = AES.block_size
    return data + (block_size - len(data) % block_size) * b'\0'

def encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode()))
    return base64.b64encode(cipher.iv + ciphertext).decode()

def decrypt(ciphertext, key):
    data = base64.b64decode(ciphertext.encode())
    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(ciphertext).rstrip(b'\0').decode()
    return decrypted_message

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        choice = request.form['choice']
        key = request.form['key'].encode()
        message = request.form['message']

        if len(key) != KEY_SIZE:
            return "Invalid key length. Key must be {} bytes long.".format(KEY_SIZE)

        if choice == 'encrypt':
            encrypted_message = encrypt(message, key)
            return render_template('index1.html', result=encrypted_message)
        elif choice == 'decrypt':
            decrypted_message = decrypt(message, key)
            return render_template('index1.html', result=decrypted_message)

    return render_template('index1.html', result=None)

if __name__ == '__main__':
    app.run(debug=True)

