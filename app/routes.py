from flask import render_template, request, redirect, url_for, flash,session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required
from .application import app, db, login_manager
from .models import User
from flask_login import current_user
from flask_login import logout_user
from .models import Key
import hashlib
import qrcode
import os
from io import BytesIO
from flask import Flask, render_template, request, send_file
import secrets
from .app1 import encrypt_data, decrypt_data
import os,io
from .app2 import encrypt, decrypt
import random
import smtplib


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # secret_pin = request.form['secret_pin']  # Add secret_pin field

        user = User.query.filter_by(username=username).first()

        if len(password) < 7:
            flash('Password must be at least 7 characters.', category='error')
        # elif len(secret_pin) != 4:  # Ensure secret PIN is 4 characters
        #     flash('Secret PIN must be 4 characters.', category='error')
        else:
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = User(username=username, password=hashed_password)  # Include secret_pin,, secret_pin=secret_pin
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)  # Start user session
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html')
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(current_user.id)
    return render_template('dashboard.html', user=user)

@app.route('/eg/')
def eg():
    return render_template('eg.html')
@app.route('/video/')
def video():
    return render_template('video.html')
@app.route('/blog/')
def blog():
    return render_template('blog.html')

@app.route('/file_encryption', methods=['GET', 'POST'])
@login_required
def file_encryption():
    if request.method == 'POST':
        secret_key = request.form['key'].encode('utf-8')
        KEY_SIZE = 32
        
        if len(secret_key) != KEY_SIZE:
            flash("Invalid key length. Key must be {} bytes long.".format(KEY_SIZE), 'danger')
            return redirect(url_for('file_encryption'))
        
        uploaded_file = request.files['file']  # Get the uploaded file

        if 'encrypt' in request.form:
            # Encrypt the file
            encrypted_data = encrypt_data(uploaded_file.read(), secret_key)

            # Get the original file name
            original_filename = uploaded_file.filename

            # Create a unique encrypted filename
            encrypted_filename = original_filename + '.enc'

            return send_file(
                io.BytesIO(encrypted_data),
                as_attachment=True,
                download_name=encrypted_filename,
                mimetype='application/octet-stream'
            )
        elif 'decrypt' in request.form:
            # Decrypt the file
            decrypted_data = decrypt_data(uploaded_file.read(), secret_key)

            # Extract the original file name from the uploaded file name
            original_filename, _ = os.path.splitext(uploaded_file.filename)

            return send_file(
                io.BytesIO(decrypted_data),
                as_attachment=True,
                download_name=original_filename,
                mimetype='application/octet-stream'
            )

    return render_template('index.html')

@app.route('/message_encryption', methods=['GET', 'POST'])
@login_required
def message_encryption():
    if request.method == 'POST':
        choice = request.form['choice']
        key = request.form['key'].encode()
        message = request.form['message']
        KEY_SIZE=32
        if len(key) != KEY_SIZE:
            flash('Invalid key length. Key must be {} bytes long.'.format(KEY_SIZE), 'error')
        else:
            if choice == 'encrypt':
                encrypted_message = encrypt(message, key)
                return render_template('index1.html', result=encrypted_message)
            elif choice == 'decrypt':
                decrypted_message = decrypt(message, key)
                return render_template('index1.html', result=decrypted_message)

    return render_template('index1.html', result=None)
@app.route('/file_decryption', methods=['GET', 'POST'])
@login_required
def file_decryption():
    if request.method == 'POST':
        secret_key = request.form['key'].encode('utf-8')
        KEY_SIZE = 32
        
        if len(secret_key) != KEY_SIZE:
            flash("Invalid key length. Key must be {} bytes long.".format(KEY_SIZE), 'danger')
            return redirect(url_for('file_decryption'))
        
        uploaded_file = request.files['file']  # Get the uploaded file

        if uploaded_file.filename.endswith('.enc'):
            # Decrypt the file
            decrypted_data = decrypt_data(uploaded_file.read(), secret_key)

            # Extract the original file name from the uploaded file name
            original_filename, _ = os.path.splitext(uploaded_file.filename)

            return send_file(
                io.BytesIO(decrypted_data),
                as_attachment=True,
                download_name=original_filename,
                mimetype='application/octet-stream'
            )
        else:
            flash("Invalid file format. Only .enc files can be decrypted.", 'danger')
            return redirect(url_for('file_decryption'))

    return render_template('file_decryption.html')
@app.route('/key_manager')
@login_required
def key_manager():
    # keys = Key.query.filter_by(user_id=current_user.id).all()
    keys = Key.query.all()
    otp = session.get('otp')
    return render_template('key_manager.html', keys=keys, otp=otp)
    # return render_template('key_manager.html', keys=keys)

@app.route('/add_key', methods=['POST'])
@login_required
def add_key():
    name = request.form['name']
    key_value = request.form['key']
    new_key = Key(name=name, key=key_value, user_id=current_user.id)
    db.session.add(new_key)
    db.session.commit()
    flash('Key added successfully.', 'success')
    return redirect(url_for('key_manager'))

@app.route('/send_otp', methods=['GET', 'POST'])
def send_otp():
     if request.method == 'POST':
          username = request.form['username']
          password = request.form['password']
          user = User.query.filter_by(username=username).first()
          if user and check_password_hash(user.password, password):
               email = username
               otp = str(random.randint(1000, 9999))
               message = 'Your OTP is  ' + otp + '  sent by SecureFileX. Please use this OTP to see your secret key.'
               server = smtplib.SMTP('smtp.gmail.com', 587)
               server.starttls()
               server.login('secruefilex@gmail.com', 'ysmg onbf kmot unfv')
               server.sendmail('secruefilex@gmail.com', email, message)
    # Store the OTP in the session for verification
               session['otp'] = otp
               session['email'] = email
               return redirect(url_for('key_manager'))

@app.route('/verify_pin', methods=['GET','POST'])
def verify_pin():
    # Get the OTP and email from the session
    otp = session.get('otp')
    email = session.get('email')
    if not otp or not email:
        return "Error: OTP not sent."

    # Get the entered PIN from the form
    entered_pin = request.form['pin']

    if entered_pin == otp:
        # PIN is correct, show the keys
        pinMatched = True
        keys =Key.query.all()  # Implement a function to retrieve keys
        return render_template('key_manager.html', keys=keys , pinMatched=pinMatched)
    else:
        # PIN is incorrect, show an error message
        return "Error: Incorrect PIN. Please try again."



@app.route('/delete_key/<int:key_id>', methods=['GET', 'POST'])
@login_required
def delete_key(key_id):
    key = Key.query.get_or_404(key_id)
    db.session.delete(key)
    db.session.commit()
    flash('Key deleted successfully.', 'success')
    return redirect(url_for('key_manager'))

@app.route('/fileint', methods=['GET', 'POST'])
@login_required
def fileint():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
        else:
            uploaded_file = request.files['file']
            if uploaded_file.filename == '':
                flash('No selected file', 'error')
            else:
                file_content = uploaded_file.read()
                uploaded_file_hash = calculate_hash(file_content)
                return render_template('fileint.html', uploaded_file_hash=uploaded_file_hash)
    return render_template('fileint.html')

def calculate_hash(file_content):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_content)
    return sha256_hash.hexdigest()


@app.route('/generate_qr', methods=['GET', 'POST'])
@login_required
def generate_qr():
    if request.method == 'POST':
        key = request.form['key']
        file_info = request.form['file_info']

        # Combine the key and file information into one string
        combined_data = f"Key: {key}\nFile Information: {file_info}"

        # Create a QR code for the combined data
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(combined_data)
        qr.make(fit=True)

        # Create a QR code image as BytesIO
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img_bytes = BytesIO()
        qr_img.save(qr_img_bytes, format='PNG')
        qr_img_bytes.seek(0)

        # Send the QR code image as a downloadable file
        return send_file(qr_img_bytes, as_attachment=True, download_name='combined_qr.png')

    return render_template('qr.html')

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)))

# Define the path to the malwarehashes.txt file inside the application folder
MALICIOUS_HASHES_FILE = os.path.join(UPLOAD_FOLDER, 'malwarehashes.txt')

# ... (the rest of your imports and setup code)
def calculate_file_hash(file, hash_algorithm='sha256'):
    """Calculate the hash of a file."""
    hash_obj = hashlib.new(hash_algorithm)
    while True:
        chunk = file.read(4096)  # Read in 4k chunks
        if not chunk:
            break
        hash_obj.update(chunk)
    return hash_obj.hexdigest()

def is_malicious(file_hash):
    """Check if a file hash is in the list of known malicious hashes."""
    with open(MALICIOUS_HASHES_FILE, 'r') as file:
        malicious_hashes = {line.strip() for line in file}
        return file_hash in malicious_hashes
@app.route('/malscan', methods=['GET', 'POST'])
def malscan():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file:
            file_hash = calculate_file_hash(file)
            if is_malicious(file_hash):
                flash('Malicious file detected!')
            else:
                flash('File is not malicious.')

    return render_template('malscan.html')

@app.route('/generate_key', methods=['GET', 'POST'])
def generate_key():
    secret_key = None

    if request.method == 'POST':
        key_length = int(request.form['key_length'])
        secret_key = secrets.token_hex(key_length // 2)  # Convert character length to byte length

    return render_template('keyrun.html', secret_key=secret_key)

from flask import Flask, render_template, request, send_file
from PyPDF2 import PdfFileReader, PdfFileWriter
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

def add_watermark(file, watermark_text):
    pdf = PdfFileReader(file)
    pdf_writer = PdfFileWriter()

    # Create a BytesIO buffer for the watermark PDF
    packet = BytesIO()
    c = canvas.Canvas(packet, pagesize=letter)
    width, height = letter

    # Set the position and attributes of the watermark text
    c.setFont("Helvetica", 36)
    c.setFillAlpha(0.2)
    c.setStrokeAlpha(0.2)
    text_width = c.stringWidth(watermark_text, "Helvetica", 36)
    text_height = 36
    x = (width - text_width) / 2
    y = (height - text_height) / 2
    c.saveState()
    c.drawString(x, y, watermark_text)
    c.restoreState()
    c.save()

    packet.seek(0)
    new_pdf = PdfFileReader(packet)
    page = pdf.getPage(0)
    page.mergePage(new_pdf.getPage(0))
    pdf_writer.addPage(page)

    # Create a BytesIO buffer for the watermarked PDF
    output_buffer = BytesIO()
    pdf_writer.write(output_buffer)
    output_buffer.seek(0)
    
    return output_buffer

@app.route('/watermark', methods=['GET', 'POST'])
def watermark():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file part"

        file = request.files['file']
        watermark_text = request.form.get('watermark_text', 'Watermark Text')

        if file.filename == '':
            return "No selected file"

        if file:
            # Add a transparent watermark to the PDF
            watermarked_pdf = add_watermark(file, watermark_text)

            # Send the watermarked PDF as a downloadable file
            return send_file(
                watermarked_pdf,
                as_attachment=True,
                download_name='watermarked.pdf',
                mimetype='application/pdf',
            )

    return render_template('watermark.html')
