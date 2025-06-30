from flask import Flask, request, jsonify
import pdfplumber

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_pdf():
    if 'pdf' not in request.files:
        return jsonify({'error': 'no file'}), 400
    file = request.files['pdf']
    results = []
    with pdfplumber.open(file.stream) as pdf:
        for i, page in enumerate(pdf.pages, start=1):
            text = page.extract_text() or ''
            results.append({'page': i, 'text': text})
    return jsonify({'pages': results})

if __name__ == '__main__':
    app.run(port=5000)
