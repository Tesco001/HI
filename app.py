from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

key = b'ThisIsASecretKey'
iv = b'ThisIsAnInitVect'

def encrypt(text):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(text.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted).decode()

def decrypt(cipher_text):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decoded = base64.b64decode(cipher_text)
    decrypted = cipher.decrypt(decoded)
    return unpad(decrypted, AES.block_size).decode()

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    input_text = ""
    mode = "Encrypt"

    if request.method == 'POST':
        input_text = request.form['text']
        mode = request.form['mode']

        try:
            if mode == 'Encrypt':
                result = encrypt(input_text)
            else:
                result = decrypt(input_text)
        except Exception as e:
            result = f"❌ Error: {str(e)}"

    return render_template('index.html', result=result, input_text=input_text, mode=mode)

if __name__ == '__main__':
    app.run(debug=True)