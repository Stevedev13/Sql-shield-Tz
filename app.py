from flask import Flask, render_template, request, redirect, session, flash, jsonify, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import re
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.permanent_session_lifetime = timedelta(minutes=30)  # Session expires after 30 minutes
CORS(app, supports_credentials=True)

# Rate limiting setup
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def get_db_connection():
    """Create and return a database connection with row factory"""
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    """Initialize database with improved schema"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        conn.commit()

def validate_input(*inputs):
    """Validate user input against common attack patterns"""
    for input_str in inputs:
        if not isinstance(input_str, str):
            return False
        if not re.match(r'^[\w.@+-]{3,50}$', input_str.strip()):
            return False
    return True

@app.route('/')
def index():
    """Home page with session check"""
    if 'user' in session:
        return f"<h1>Welcome back, {session['user']}!</h1><a href='/logout'>Logout</a>"
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    """Improved registration endpoint with validation"""
    if request.method == 'POST':
        try:
            # Get data based on content type
            if request.is_json:
                data = request.get_json()
                username = data.get('username', '').strip()
                email = data.get('email', '').strip()
                password = data.get('password', '')
            else:
                username = request.form.get('username', '').strip()
                email = request.form.get('email', '').strip()
                password = request.form.get('password', '')

            # Validate input
            if not all([username, email, password]):
                raise ValueError("All fields are required")
            if not validate_input(username, email, password):
                raise ValueError("Invalid input characters")
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters")

            # Secure password hashing
            hashed_password = generate_password_hash(
                password,
                method='pbkdf2:sha256',
                salt_length=16
            )

            with get_db_connection() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                        (username, email, hashed_password)
                    )
                    conn.commit()
                    
                    response_data = {
                        'success': True,
                        'message': 'Registration successful'
                    }
                    if request.is_json:
                        return jsonify(response_data), 201
                    
                    flash(response_data['message'], "success")
                    return redirect('/login')
                
                except sqlite3.IntegrityError as e:
                    error_msg = "Username or email already exists"
                    if "users.email" in str(e):
                        error_msg = "Email already exists"
                    raise ValueError(error_msg)

        except ValueError as e:
            error_response = {
                'success': False,
                'message': str(e)
            }
            if request.is_json:
                return jsonify(error_response), 400
            flash(str(e), "danger")
            return redirect('/register')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """Secure login endpoint with improved validation"""
    if request.method == 'POST':
        try:
            # Get credentials
            if request.is_json:
                data = request.get_json()
                email = data.get('email', '').strip()  # Changed to expect email
                password = data.get('password', '')
            else:
                email = request.form.get('email', '').strip()  # Changed to expect email
                password = request.form.get('password', '')

            # Validate input
            if not all([email, password]):
                raise ValueError("Email and password are required")
            if not validate_input(email, password):
                raise ValueError("Invalid input format")

            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM users WHERE email = ?",
                    (email,)
                )
                user = cursor.fetchone()

                if user and check_password_hash(user['password'], password):
                    # Update last login time
                    cursor.execute(
                        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                        (user['id'],)
                    )
                    conn.commit()

                    # Set session
                    session['user'] = {
                        'id': user['id'],
                        'username': user['username'],
                        'email': user['email']
                    }

                    response_data = {
                        'success': True,
                        'message': 'Login successful',
                        'user': dict(user)  # Convert Row to dict for JSON
                    }
                    if request.is_json:
                        return jsonify(response_data), 200
                    
                    return redirect('/')
                
                raise ValueError("Invalid email or password")

        except ValueError as e:
            error_response = {
                'success': False,
                'message': str(e)
            }
            if request.is_json:
                return jsonify(error_response), 401
            flash(str(e), "danger")
            return redirect('/login')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Secure logout with session cleanup"""
    session.pop('user', None)
    flash("You have been logged out successfully", "info")
    return redirect('/')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'success': False,
        'message': 'Too many requests'
    }), 429

if __name__ == '__main__':
    init_db()
    app.run(debug=os.environ.get('FLASK_DEBUG', False))