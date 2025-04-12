import os
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, session, flash
import MySQLdb
import paramiko
import urllib
import requests
from werkzeug.utils import secure_filename
import bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import magic
from flask import jsonify
from patch_utils import execute_patch, upload_patch_to_remote
from pfsense_patch_manager import log_patch_activity, upload_patch as pfsense_upload_patch
from pfsense_patch_manager import apply_patch as pfsense_apply_patch
from pfsense_patch_manager import rollback_patch as pfsense_rollback_patch
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address  


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure key

@app.errorhandler(413)  # Handle large file errors
def request_entity_too_large(error):
    return jsonify({'error': 'File size exceeds the 10MB limit!'}), 413

# Configure MySQL Database Connection for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:RUCHI%40%40123%21@crossover.proxy.rlwy.net:45003/railway'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout: 30 minutes

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"] 
)

# Initialize the database
db = SQLAlchemy(app)

# Ensure the upload directory exists
UPLOAD_FOLDER = 'static/patches'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOADED_PATCHES_DEST'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB limit
ALLOWED_EXTENSIONS = {'zip', 'tar', 'gz', 'sh', 'bat', 'tgz', 'xml', 'conf'}
app.config['ALLOWED_EXTENSIONS'] = {'zip', 'tar', 'gz', 'sh', 'tgz', 'xml', 'conf'}




# In main.py - is_patch_safe function
def is_patch_safe(file_path):
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read()

    dangerous_signatures = ['rm -rf', 'dd if=', 'wget ', 'curl ', 'nc -lvp', 'python -c', 'mkfs', 'chmod 777 /', 'chown root', 'exec', 'shutdown', 'reboot']
    for danger in dangerous_signatures:
        if danger in content:
            return False, danger  # Dangerous command found
    return True, None




def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config.get('ALLOWED_EXTENSIONS', set())

def is_valid_file(file_path):
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(file_path)
    return file_type in ['application/zip', 'application/x-tar', 'application/gzip', 'application/x-sh']

# Helper Function: Get Client IP Address
def get_client_ip():
    return request.remote_addr

@app.before_request
def make_session_secure():
    session.permanent = True  # Make session expire based on timeout
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
    app.config['SESSION_COOKIE_SECURE'] = os.getenv("FLASK_ENV") == "production"

# Database connection function
def get_database_connection():
    try:
        connection = MySQLdb.connect(
            host='localhost',
            user='root',
            passwd='RUCHI@@123!',
            db='register',
            port=3306
        )
        return connection
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

# Define the Updated Patches Model
class Patches(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(200), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    uploaded_by = db.Column(db.Integer, nullable=False)
    uploaded_from_ip = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')
    patch_version = db.Column(db.String(50), nullable=False)
    os_type = db.Column(db.String(50), nullable=False)
    downloaded_from_ip = db.Column(db.String(50), nullable=True)
    downloaded_by = db.Column(db.Integer, nullable=True)

# Define Patch Logs Model
class PatchLogs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patch_id = db.Column(db.Integer, db.ForeignKey('patches.id'), nullable=False)
    action = db.Column(db.Enum('uploaded', 'downloaded', 'applied', 'rolled_back'), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# Ensure MySQL tables are created
with app.app_context():
    db.create_all()

# Home Route (Redirect to Register)
@app.route('/')
def home():
    return redirect(url_for('register'))

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        connection = get_database_connection()
        if connection:
            cursor = connection.cursor(MySQLdb.cursors.DictCursor)

            # 🔍 Check if email already exists
            cursor.execute("SELECT * FROM register WHERE email = %s", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                cursor.close()
                connection.close()
                return jsonify({'success': False, 'message': 'Email already exists'}), 400

            # ✅ If email is unique, proceed with registration
            query = "INSERT INTO register (username, email, password, phone) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (username, email, hashed_password, phone))
            connection.commit()
            cursor.close()
            connection.close()

            return jsonify({'success': True, 'message': 'Registration successful!'}), 200
        else:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500

    return render_template('register.html')

# Index Route (After Login, show index page first)
@app.route('/index')
def index():
    if 'user_id' not in session:
        flash("Session expired or unauthorized access. Please log in.", "warning")
        return redirect(url_for('login'))

    return render_template('index.html', username=session.get('username'))

# Login Route with JSON Response & Rate Limiting
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['loginEmail']
        password = request.form['loginPassword']

        connection = get_database_connection()
        if connection:
            cursor = connection.cursor(MySQLdb.cursors.DictCursor)
            query = "SELECT * FROM register WHERE email = %s"
            cursor.execute(query, (email,))
            user = cursor.fetchone()
            cursor.close()
            connection.close()

            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                session['user_id'] = user['id']
                session['username'] = user['username']
                return jsonify({'success': True, 'message': 'Login successful!'}), 200
            else:
                return jsonify({'success': False, 'message': 'Invalid email or password'}), 401

    return render_template('login.html')


@app.route('/upload_patch', methods=['POST'])
def upload_patch():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 401

    file = request.files.get('patchFile')
    patch_version = request.form.get('patchVersion', 'N/A')
    os_type = request.form.get('osType', 'N/A').lower()

    if not file or file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file!'}), 400

    # Validate file extension
    filename = secure_filename(file.filename)
    if not allowed_file(filename):
        return jsonify({'success': False, 'message': 'Invalid file type! Allowed: zip, tar, gz, sh, tgz, xml, conf'}), 400

    # Save the file to the correct folder
    file_path = os.path.join(app.config['UPLOADED_PATCHES_DEST'], filename)
    file.save(file_path)

    # Ensure the file is successfully saved before proceeding
    if not os.path.exists(file_path):
        return jsonify({'success': False, 'message': 'Failed to save the file on the server!'}), 500

    # Save patch details to the database (without uploading to pfSense yet)
    new_patch = Patches(
        file_name=filename,
        file_path=file_path,
        uploaded_by=session['user_id'],
        uploaded_from_ip=get_client_ip(),
        patch_version=patch_version,
        os_type=os_type
    )

    db.session.add(new_patch)
    db.session.commit()

    # Log the upload action
    log_entry = PatchLogs(
        patch_id=new_patch.id,
        action="uploaded",
        user_id=session['user_id'],
        ip_address=get_client_ip(),
        timestamp=datetime.now(timezone.utc)
    )
    db.session.add(log_entry)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Patch uploaded successfully!'}), 200

    
# Apply Patch Route
# In main.py - apply_patch route
@app.route('/apply_patch/<int:patch_id>', methods=['POST'])
def apply_patch(patch_id):
    if 'user_id' not in session:
        flash("Unauthorized access! Please log in.", "danger")
        return redirect(url_for('login'))

    patch = db.session.get(Patches, patch_id)
    if not patch:
        flash("Patch not found!", "danger")
        return redirect(url_for('dashboard'))

    if patch.status.lower() != 'pending':
        flash("Patch already applied!", "warning")
        return redirect(url_for('dashboard'))

    # Perform content-aware malware scan before execution
    is_safe, danger = is_patch_safe(patch.file_path)
    if not is_safe:
        flash(f"Patch blocked: contains dangerous command `{danger}`", "danger")
        return jsonify({'success': False, 'message': f'Patch blocked: contains dangerous command `{danger}`'})

    remote_host = "192.168.56.2"
    username = "admin"
    password = "pfsense"



    remote_patch_path = upload_patch_to_remote(patch.file_path, remote_host, username, password)
    if not remote_patch_path:
        flash(f"Patch upload failed!", "danger")
        return redirect(url_for('dashboard'))

    patch_applied = execute_patch(remote_host, username, password, remote_patch_path, patch.os_type)

    if patch_applied:
        patch.status = 'applied'
        db.session.commit()
        flash(f"Patch '{patch.file_name}' has been successfully applied!", "success")

        log_patch_activity("applied", patch.id, session['user_id'])
        return jsonify({'success': True, 'message': "Patch applied successfully!"})
    else:
        flash(f"Patch '{patch.file_name}' failed to apply.", "danger")
        return jsonify({'success': False, 'message': "Failed to apply patch!"})


# Function to execute the patch on remote system
def execute_patch(remote_host, username, password, patch_path, os_type=None):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh_client.connect(remote_host, username=username, password=password)

        # Ensure the patch file exists at the specified location
        stdin, stdout, stderr = ssh_client.exec_command(f"ls {patch_path}")
        file_check = stdout.read().decode()
        if "No such file" in file_check:
            print(f"❌ Patch file {patch_path} not found!")
            return False

        # Execute the patch based on OS type
        if os_type == 'linux':
            print(f"⚡ Running command: sh {patch_path}")
            stdin, stdout, stderr = ssh_client.exec_command(f"sh {patch_path}")
        elif os_type == "pfsense":
            print(f"⚡ Running command: pfSsh.php playback patch_apply {patch_path}")
            stdin, stdout, stderr = ssh_client.exec_command(f"pfSsh.php playback patch_apply {patch_path}")
        else:
            print(f"⚡ Running command for unknown OS: {patch_path}")
            stdin, stdout, stderr = ssh_client.exec_command(f"sh {patch_path}")

        output = stdout.read().decode()
        error = stderr.read().decode()

        print(f"🔹 STDOUT: {output}")
        print(f"🔸 STDERR: {error}")

        if error:
            print(f"⚠️ Execution Error: {error}")
            return False

        print(f"✅ Patch Execution Output: {output}")
        return True

    except Exception as e:
        print(f"❌ Error executing patch: {e}")
        return False
    finally:
        ssh_client.close()


# Function to upload patch to a remote system
def upload_patch_to_remote(file_path, remote_host, username, password, remote_path="/tmp/"):
    """Uploads a patch file to a remote machine after cleaning line endings"""
    try:
        print(f"🔄 Uploading {file_path} to {remote_host}...")

        # 🧼 Clean line endings (convert Windows \r\n → Unix \n)
        with open(file_path, 'rb') as f:
            content = f.read()
        cleaned = content.replace(b'\r\n', b'\n')
        with open(file_path, 'wb') as f:
            f.write(cleaned)

        # Connect via SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(remote_host, username=username, password=password)

        # Upload using SFTP
        sftp = ssh_client.open_sftp()
        remote_file_path = os.path.join(remote_path, os.path.basename(file_path))
        print(f"🔹 Uploading to: {remote_file_path}")
        sftp.put(file_path, remote_file_path)
        sftp.close()

        print(f"✅ Patch uploaded successfully to: {remote_file_path}")
        return remote_file_path

    except Exception as e:
        print(f"❌ Upload failed: {e}")
        return None
    finally:
        ssh_client.close()


# Rollback Patch Route
@app.route('/rollback_patch/<int:patch_id>', methods=['POST'])
def rollback_patch(patch_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    patch = Patches.query.get(patch_id)
    if patch and patch.status == 'applied':
        patch.status = 'pending'
        db.session.commit()

        log_entry = PatchLogs(
            patch_id=patch.id,
            action="rolled_back",
            user_id=session['user_id'],
            ip_address=get_client_ip(),
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()

        flash(f"Patch '{patch.file_name}' has been rolled back and is now pending again!", "success")
    else:
        flash("Patch not found or cannot be rolled back!", "danger")

    return redirect(url_for('dashboard'))

# Download Patch Route
@app.route('/download_patch/<filename>')
def download_patch(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    patch = Patches.query.filter_by(file_name=filename).first()
    if patch:
        patch.downloaded_from_ip = get_client_ip()
        patch.downloaded_by = session['user_id']

        log_entry = PatchLogs(
            patch_id=patch.id,
            action="downloaded",
            user_id=session['user_id'],
            ip_address=get_client_ip(),
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()

    file_path = os.path.join(app.config['UPLOADED_PATCHES_DEST'], filename)
    if os.path.exists(file_path):
        return send_from_directory(app.config['UPLOADED_PATCHES_DEST'], filename, as_attachment=True)
    else:
        flash("File not found!", "danger")
        return redirect(url_for('dashboard'))
    


# Search Route for Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    search_query = request.args.get('query', '').strip()
    os_type = request.args.get('os_type', '').strip()
    status = request.args.get('status', '').strip()

    patches = Patches.query.order_by(Patches.upload_date.desc())

    if search_query:
        patches = patches.filter(Patches.file_name.ilike(f'%{search_query}%'))
    if os_type:
        patches = patches.filter(Patches.os_type.ilike(f'%{os_type}%'))
    if status:
        patches = patches.filter(Patches.status == status)

    patches = patches.all()

    latest_patch = Patches.query.order_by(Patches.upload_date.desc()).first()

    # Add warning_message for blocked patches
    warning_message = None
    if 'warning_message' in session:
        warning_message = session['warning_message']
        session.pop('warning_message', None)  # Clear session warning

    return render_template(
        'dashboard.html',
        username=session['username'],
        patches=patches,
        latest_patch=latest_patch,
        search_query=search_query,
        os_type=os_type,
        status=status,
        warning_message=warning_message  # Pass warning message to the template
    )


# Logout Route
@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    flash("You have been logged out successfully!", "info")
    return redirect(url_for('login'))

@app.route('/welcome')
def welcome():
    if 'username' in session:
        return render_template('welcome.html')
    else:
        return redirect(url_for('login'))

@app.route('/scan_patch')
def scan_patch():
    filename = request.args.get('filename')
    patch = Patches.query.filter_by(file_name=filename).first()
    if not patch:
        return jsonify({'safe': False, 'dangerous_command': 'Patch not found'}), 404

    is_safe, danger = is_patch_safe(patch.file_path)
    return jsonify({
        'safe': is_safe,
        'dangerous_command': danger if danger else ''
    })




if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)