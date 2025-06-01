# Sql-shield-Tz

## How to Run the Flask App

1. **Install dependencies** (if not already):
   ```powershell
   pip install -r requirements.txt
   ```

2. **Run the Flask server:**
   ```powershell
   python app.py
   ```
   The server will start at `http://127.0.0.1:5000` by default.

3. **Open the app:**
   - Open `Template/index.html` in your browser (preferably served via a local web server for full functionality).

---

## How the App Works

- **Landing Page:**
  - `index.html` provides an introduction and links to Register and Login.

- **Register:**
  - Users can register with a username, email, and password.
  - Registration data is sent to the Flask backend (`/register`), which stores it in a SQLite database.

- **Login:**
  - Users log in using their email and password.
  - Login data is sent to the Flask backend (`/login`), which checks credentials.
  - On success, the user is redirected to `home.html`.

- **Home Page:**
  - Shows a welcome message and a logout option.
  - Logout clears the session and returns to the login page.

- **Security Demo:**
  - The app demonstrates SQL Injection risks in authentication forms.

---

> **Note:**
> For full functionality (API calls), run the HTML files via a local web server (not by double-clicking). You can use Python's built-in server:
> ```powershell
> cd Template
> python -m http.server 8000
> ```
> Then visit `http://localhost:8000/index.html` in your browser.