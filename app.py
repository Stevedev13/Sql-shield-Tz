from flask import Flask, render_template, request, redirect, session, flash, jsonify
from flask_cors import CORS
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'secure_session_key'
CORS(app)

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            password = hashlib.md5(data.get('password', '').encode()).hexdigest()
        else:
            username = request.form['username'].strip()
            email = request.form['email'].strip()
            password = hashlib.md5(request.form['password'].encode()).hexdigest()
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, password))
            conn.commit()
            if request.is_json:
                return jsonify({'success': True, 'message': 'Registration successful'}), 200
            flash("Registration successful", "success")
            return redirect('/login')
        except sqlite3.IntegrityError:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Username already exists'}), 400
            flash("Username already exists", "danger")
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            email = data.get('username', '').strip()  # frontend sends 'username' field, use as email
            password = hashlib.md5(data.get('password', '').encode()).hexdigest()
        else:
            email = request.form['username'].strip()  # frontend sends 'username' field, use as email
            password = hashlib.md5(request.form['password'].encode()).hexdigest()
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
        user = cursor.fetchone()
        conn.close()
        if user:
            session['user'] = email
            if request.is_json:
                return jsonify({'success': True, 'message': 'Login successful'}), 200
            return f"<h1>Welcome, {email}!</h1><a href='/logout'>Logout</a>"
        else:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully", "info")
    return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
