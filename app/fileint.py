import hashlib
from flask import Flask, request, render_template

app = Flask(__name__)

def calculate_hash(data):
    sha256_hash = hashlib.sha256()
    while True:
        chunk = data.read(65536)  # Read in 64KB chunks
        if not chunk:
            break
        sha256_hash.update(chunk)
    return sha256_hash.hexdigest()



@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'

        uploaded_file = request.files['file']

        if uploaded_file.filename == '':
            return 'No selected file'

        if uploaded_file:
            # Calculate hash for the uploaded file
            uploaded_file_hash = calculate_hash(uploaded_file.stream)

            # Provide the hash value for comparison
            return render_template('fileint.html', uploaded_file_hash=uploaded_file_hash)

    return render_template('fileint.html')

if __name__ == '__main__':
    app.run(debug=True)