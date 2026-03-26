# Vaultify — Secure Password Manager

A full-stack secure password manager with a **Python Flask + MySQL** backend and a **vanilla JS SPA** frontend.

---

## Project Structure

```
Vaultify/
├── app.py                # Flask app factory & entry point
├── config.py             # Env var loader
├── db.py                 # PyMySQL connection helper
├── schema.sql            # One-time DB setup script
├── requirements.txt      # Python dependencies
├── .env.example          # Environment variable template
│
├── routes/
│   ├── auth_routes.py    # POST /api/auth/register & /login
│   └── password_routes.py# CRUD /api/passwords (JWT-protected)
│
├── utils/
│   ├── auth.py           # bcrypt hashing + JWT generation
│   └── crypto.py         # Fernet AES-128 encrypt/decrypt
│
├── index.html            # SPA frontend
├── style.css             # Dark-theme styling
└── script.js             # Frontend JS — calls Flask API
```

---

## Setup & Run

### 1 — Prerequisites

- Python 3.9+
- MySQL 8.0+

### 2 — Database

```bash
mysql -u root -p < schema.sql
```

### 3 — Python Environment

```bash
cd e:\Vaultify
python -m venv venv
venv\Scripts\activate       # Windows
pip install -r requirements.txt
```

### 4 — Environment Variables

```bash
copy .env.example .env
```

Edit `.env` and fill in:

| Variable | How to generate |
|----------|----------------|
| `DB_PASSWORD` | Your MySQL root password |
| `JWT_SECRET_KEY` | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `FERNET_KEY` | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

### 5 — Run the Server

```bash
python app.py
```

Flask starts at `http://localhost:5000`.

### 6 — Open the Frontend

Open `index.html` in your browser (or serve it with Live Server).  
The frontend talks to `http://localhost:5000/api` by default.

---

## API Reference

### Auth

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| POST | `/api/auth/register` | `{"username","password"}` | `201 {"message"}` |
| POST | `/api/auth/login` | `{"username","password"}` | `200 {"token","user_id","username"}` |

### Passwords *(require `Authorization: Bearer <token>`)*

| Method | Endpoint | Body / Params | Response |
|--------|----------|--------------|----------|
| GET | `/api/passwords` | — | `200 {"passwords":[…]}` |
| POST | `/api/passwords` | `{"site","site_username","password"}` | `201 {"message","id"}` |
| PUT | `/api/passwords/<id>` | any subset of above | `200 {"message"}` |
| DELETE | `/api/passwords/<id>` | — | `200 {"message"}` |

### Health Check

```
GET /api/health  →  200 {"status":"ok"}
```

---

## Sample cURL Requests

```bash
# Register
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Str0ng@Pass"}'

# Login — copy the token from the response
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Str0ng@Pass"}'

# Store a password
curl -X POST http://localhost:5000/api/passwords \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"site":"Google","site_username":"alice@gmail.com","password":"G00gle@2024"}'

# Retrieve passwords
curl -X GET http://localhost:5000/api/passwords \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# Update a password (id = 1)
curl -X PUT http://localhost:5000/api/passwords/1 \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"password":"NewP@ss2024!"}'

# Delete a password (id = 1)
curl -X DELETE http://localhost:5000/api/passwords/1 \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

---

## Security Notes

- User passwords are hashed with **bcrypt** (cost factor 12) — never stored in plain text.
- Site passwords are encrypted with **Fernet (AES-128-CBC + HMAC-SHA256)** — only decrypted server-side on request.
- All DB queries use **parameterized statements** — no SQL injection possible.
- **JWT** tokens expire after 24 hours (configurable via `JWT_EXPIRY_HOURS`).
- Secrets are loaded from `.env` — never hard-coded.
