from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from PIL import Image
import stepic
from cryptography.fernet import Fernet
import base64
import os
import io
import secrets

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

def generate_key():
    """Generate encryption key"""
    return Fernet.generate_key()

def encrypt_text(text, key):
    """Encrypt text using Fernet"""
    fernet = Fernet(key)
    encrypted_text = fernet.encrypt(text.encode())
    return base64.urlsafe_b64encode(encrypted_text).decode()

def decrypt_text(encrypted_text, key):
    """Decrypt text using Fernet"""
    try:
        fernet = Fernet(key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode())
        decrypted_text = fernet.decrypt(encrypted_bytes)
        return decrypted_text.decode()
    except Exception as e:
        raise ValueError("Decryption failed. Invalid key or corrupted data.")

def hide_text_in_image(image, text, key):
    """Hide encrypted text in image"""
    # Encrypt the text
    encrypted_text = encrypt_text(text, key)
    
    # Convert image to RGB if necessary
    if image.mode != 'RGB':
        image = image.convert('RGB')
    
    # Hide the encrypted text in the image
    encoded_image = stepic.encode(image, encrypted_text.encode())
    return encoded_image

def extract_text_from_image(image, key):
    """Extract and decrypt text from image"""
    try:
        # Extract the encrypted text
        encrypted_text = stepic.decode(image)
        
        if not encrypted_text:
            raise ValueError("No hidden data found in image")
        
        # Decrypt the text
        decrypted_text = decrypt_text(encrypted_text, key)
        return decrypted_text
    except Exception as e:
        raise ValueError(f"Error extracting text: {str(e)}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/lock', methods=['GET', 'POST'])
def lock():
    if request.method == 'POST':
        # Check if files are uploaded
        if 'image' not in request.files or 'text' not in request.form:
            flash('Please upload an image and enter text')
            return redirect(request.url)
        
        image_file = request.files['image']
        text = request.form['text']
        key_input = request.form.get('key', '').strip()
        
        if image_file.filename == '':
            flash('No image selected')
            return redirect(request.url)
        
        if not text:
            flash('Please enter text to hide')
            return redirect(request.url)
        
        try:
            # Open and validate image
            image = Image.open(image_file.stream)
            
            # Generate or use provided key
            if key_input:
                # Validate the key
                try:
                    Fernet(key_input.encode())
                    key = key_input.encode()
                except:
                    flash('Invalid encryption key format')
                    return redirect(request.url)
            else:
                key = generate_key()
            
            # Hide text in image
            encoded_image = hide_text_in_image(image, text, key)
            
            # Save to bytes buffer
            img_buffer = io.BytesIO()
            encoded_image.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            # Store in session for download
            session_id = secrets.token_hex(16)
            app.config.setdefault('SESSION_DATA', {})[session_id] = {
                'image_data': img_buffer.getvalue(),
                'key': key.decode()
            }
            
            return render_template('result.html', 
                                 session_id=session_id,
                                 key=key.decode(),
                                 action='lock')
            
        except Exception as e:
            flash(f'Error processing image: {str(e)}')
            return redirect(request.url)
    
    return render_template('lock.html')

@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    if request.method == 'POST':
        if 'image' not in request.files or 'key' not in request.form:
            flash('Please upload an image and enter decryption key')
            return redirect(request.url)
        
        image_file = request.files['image']
        key = request.form['key'].strip()
        
        if image_file.filename == '':
            flash('No image selected')
            return redirect(request.url)
        
        if not key:
            flash('Please enter decryption key')
            return redirect(request.url)
        
        try:
            # Open image
            image = Image.open(image_file.stream)
            
            # Extract and decrypt text
            decrypted_text = extract_text_from_image(image, key.encode())
            
            session_id = secrets.token_hex(16)
            app.config.setdefault('SESSION_DATA', {})[session_id] = {
                'text': decrypted_text
            }
            
            return render_template('result.html',
                                 session_id=session_id,
                                 extracted_text=decrypted_text,
                                 action='unlock')
            
        except Exception as e:
            flash(f'Error extracting text: {str(e)}')
            return redirect(request.url)
    
    return render_template('unlock.html')

@app.route('/download/<session_id>')
def download_image(session_id):
    session_data = app.config.get('SESSION_DATA', {})
    data = session_data.get(session_id)
    
    if not data or 'image_data' not in data:
        flash('Download link expired')
        return redirect(url_for('index'))
    
    # Clean up session data
    session_data.pop(session_id, None)
    
    return send_file(
        io.BytesIO(data['image_data']),
        mimetype='image/png',
        as_attachment=True,
        download_name='encoded_image.png'
    )

@app.route('/cleanup/<session_id>')
def cleanup(session_id):
    session_data = app.config.get('SESSION_DATA', {})
    session_data.pop(session_id, None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
