from flask import Flask, request, send_file, render_template
import qrcode
from io import BytesIO

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('qr.html')

@app.route('/generate_qr', methods=['POST'])
def generate_qr():
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

if __name__ == '__main__':
    app.run(debug=True)
