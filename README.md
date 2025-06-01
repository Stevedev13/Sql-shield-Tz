# Sql-shield-Tz

## Quick Start: Run the App (Windows & Linux)

### 1. Prepare a Virtual Environment

#### Windows (PowerShell):
```powershell
python -m venv venv
venv\Scripts\Activate
```

#### Linux/macOS (bash):
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Requirements
```bash
pip install -r requirements.txt
```

### 3. Run the Flask App
```bash
python app.py
```

The server will start at `http://127.0.0.1:5000` by default.

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
> ```bash
> cd Template
> python -m http.server 8000
> ```
> Then visit `http://localhost:8000/index.html` in your browser.

---

## Example SQLMap Command

```bash
sqlmap -u "http://localhost:5000/login" --data="username=test&password=test" --risk=3 --level=5
```