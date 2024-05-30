from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY_SIZE = 32 # AES-128 (change to 24 for AES-192 or 32 for AES-256)

def pad(data):
    block_size = AES.block_size
    return data + (block_size - len(data) % block_size) * b'\0'

def encrypt_data(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    padded_plaintext = pad(plaintext)
    ciphertext = cipher.encrypt(padded_plaintext)

    return iv + ciphertext

def decrypt_data(data, key):
    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = padded_plaintext.rstrip(b'\0')

    return plaintext
# KEY_SIZE = 16  # AES-128 (change to 24 for AES-192 or 32 for AES-256)

# def pad(data):
#     block_size = AES.block_size
#     return data + (block_size - len(data) % block_size) * b'\0'

# def encrypt_data(plaintext, key):
#     iv = get_random_bytes(AES.block_size)
#     cipher = AES.new(key, AES.MODE_CBC, iv)

#     padded_plaintext = pad(plaintext)
#     ciphertext = cipher.encrypt(padded_plaintext)

#     return iv + ciphertext

# def decrypt_data(data, key):
#     iv = data[:AES.block_size]
#     ciphertext = data[AES.block_size:]
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     padded_plaintext = cipher.decrypt(ciphertext)
#     plaintext = padded_plaintext.rstrip(b'\0')

#     return plaintext

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/encrypt', methods=['POST'])
# def encrypt():
#     secret_key = request.form['key'].encode('utf-8')

#     if len(secret_key) != KEY_SIZE:
#         return "Invalid key length. Key must be {} bytes long.".format(KEY_SIZE)

#     uploaded_file = request.files['file']  # Get the uploaded file

#     # Read the content of the uploaded file
#     plaintext = uploaded_file.read()

#     # Get the original file name
#     original_filename = uploaded_file.filename

#     iv = get_random_bytes(AES.block_size)
#     cipher = AES.new(secret_key, AES.MODE_CBC, iv)

#     padded_plaintext = pad(plaintext)
#     ciphertext = cipher.encrypt(padded_plaintext)

#     encrypted_data = iv + ciphertext

#     return send_file(
#         io.BytesIO(encrypted_data),
#         as_attachment=True,
#         download_name=original_filename + '.enc',
#         mimetype='application/octet-stream'
#     )

# @app.route('/decrypt', methods=['POST'])
# def decrypt():
#     secret_key = request.form['key'].encode()
#     uploaded_file = request.files['file']

#     if len(secret_key) != KEY_SIZE:
#         return "Invalid key length. Key must be {} bytes long.".format(KEY_SIZE)

#     encrypted_data = uploaded_file.read()

#     iv = encrypted_data[:AES.block_size]
#     ciphertext = encrypted_data[AES.block_size:]
#     cipher = AES.new(secret_key, AES.MODE_CBC, iv)
#     padded_plaintext = cipher.decrypt(ciphertext)
#     plaintext = padded_plaintext.rstrip(b'\0')

#     # Extract the original file name from the uploaded file name
#     original_filename = os.path.splitext(uploaded_file.filename)[0]

#     return send_file(
#         io.BytesIO(plaintext),
#         as_attachment=True,
#         download_name=original_filename,
#         mimetype='application/octet-stream'
#     )



# @app.route('/encrypt', methods=['POST'])
# def encrypt():
#     secret_key = request.form['key'].encode('utf-8')

#     if len(secret_key) != KEY_SIZE:
#         return "Invalid key length. Key must be {} bytes long.".format(KEY_SIZE)

#     uploaded_file = request.files['file']  # Get the uploaded file

#     # Read the content of the uploaded file
#     plaintext = uploaded_file.read()

#     iv = get_random_bytes(AES.block_size)
#     cipher = AES.new(secret_key, AES.MODE_CBC, iv)

#     padded_plaintext = pad(plaintext)
#     ciphertext = cipher.encrypt(padded_plaintext)

#     encrypted_data = iv + ciphertext

#     return send_file(
#         io.BytesIO(encrypted_data),
#         as_attachment=True,
#         download_name='encrypted_file.enc',
#         mimetype='application/octet-stream'
#     )



# @app.route('/decrypt', methods=['POST'])
# def decrypt():
#     secret_key = request.form['key'].encode()
#     uploaded_file = request.files['file']

#     if len(secret_key) != KEY_SIZE:
#         return "Invalid key length. Key must be {} bytes long.".format(KEY_SIZE)

#     encrypted_data = uploaded_file.read()
#     decrypted_data = decrypt_data(encrypted_data, secret_key)

#     return send_file(
#         io.BytesIO(decrypted_data),
#         as_attachment=True,
#         download_name='decrypted_file',
#         mimetype='application/octet-stream'
#     )

