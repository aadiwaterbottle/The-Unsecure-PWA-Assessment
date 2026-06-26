import os
import sqlite3 as sql
import time
import random
import hashlib
import bcrypt
from html import escape
import base64
import hashlib
import logging
import os
import random
import secrets
import sqlite3 as sql
import time
from html import escape

import bcrypt
import pyotp

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError as exc:
    raise RuntimeError("pycryptodome is required. Install it with: pip install pycryptodome") from exc

logger = logging.getLogger(__name__)

DATABASE_PATH = os.path.join("database_files", "database.db")


def _get_password_pepper():
    pepper = os.environ.get("PASSWORD_PEPPER")
    if not pepper:
        pepper = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
        os.environ["PASSWORD_PEPPER"] = pepper
        logger.warning("PASSWORD_PEPPER not set; using temporary fallback for this process.")
    return pepper


def _apply_password_pepper(password):
    pepper = _get_password_pepper().encode("utf-8")
    password_bytes = password.encode("utf-8")
    combined = password_bytes + b"|" + pepper
    return hashlib.sha256(combined).hexdigest()


def _derive_key():
    raw_key = os.environ.get("TOTP_ENCRYPTION_KEY")
    if not raw_key:
        raw_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
        os.environ["TOTP_ENCRYPTION_KEY"] = raw_key
        logger.warning("TOTP_ENCRYPTION_KEY not set; using temporary fallback for this process.")
    return hashlib.sha256(raw_key.encode("utf-8")).digest()


def _ensure_db_schema():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    con = sql.connect(DATABASE_PATH)
    cur = con.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            dateOfBirth TEXT,
            two_factor_secret TEXT,
            two_factor_enabled INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feedback TEXT NOT NULL
        )
        """
    )

    cur.execute("PRAGMA table_info(users)")
    existing_columns = {row[1] for row in cur.fetchall()}

    if "two_factor_secret" not in existing_columns:
        cur.execute("ALTER TABLE users ADD COLUMN two_factor_secret TEXT")
    if "two_factor_enabled" not in existing_columns:
        cur.execute("ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0")

    con.commit()
    con.close()


def _encrypt_secret(secret):
    iv = os.urandom(16)
    cipher = AES.new(_derive_key(), AES.MODE_CBC, iv)
    padded = pad(secret.encode("utf-8"), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(iv + encrypted).decode("utf-8")


def _decrypt_secret(payload):
    if not payload:
        return None
    data = base64.b64decode(payload.encode("utf-8"))
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(_derive_key(), AES.MODE_CBC, iv)
    padded = cipher.decrypt(encrypted)
    return unpad(padded, AES.block_size).decode("utf-8")


def insertUser(username, password, DoB):
    _ensure_db_schema()
    con = sql.connect(DATABASE_PATH)
    cur = con.cursor()

    peppered_password = _apply_password_pepper(password)
    hashed_password = bcrypt.hashpw(
        peppered_password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")

    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth) VALUES (?, ?, ?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()


def authenticate_user(username, password):
    _ensure_db_schema()
    con = sql.connect(DATABASE_PATH)
    cur = con.cursor()

    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    stored_user = cur.fetchone()

    if stored_user is None:
        con.close()
        return False

    stored_hash = stored_user[0]

    with open("visitor_log.txt", "r", encoding="utf-8") as file:
        number = int(file.read().strip())
        number += 1
    with open("visitor_log.txt", "w", encoding="utf-8") as file:
        file.write(str(number))

    time.sleep(random.randint(80, 90) / 1000)

    peppered_password = _apply_password_pepper(password)
    if bcrypt.checkpw(peppered_password.encode("utf-8"), stored_hash.encode("utf-8")):
        con.close()
        return True

    con.close()
    return False


def retrieveUsers(username, password):
    return authenticate_user(username, password)


def create_totp_secret(username):
    _ensure_db_schema()
    secret = pyotp.random_base32(32)
    encrypted_secret = _encrypt_secret(secret)

    con = sql.connect(DATABASE_PATH)
    cur = con.cursor()
    cur.execute(
        "UPDATE users SET two_factor_secret = ? WHERE username = ?",
        (encrypted_secret, username),
    )
    con.commit()
    con.close()

    totp = pyotp.TOTP(secret)
    otpauth_uri = totp.provisioning_uri(
        name=username,
        issuer_name="The Unsecure PWA",
    )
    return secret, otpauth_uri


def get_totp_secret(username):
    _ensure_db_schema()
    con = sql.connect(DATABASE_PATH)
    cur = con.cursor()
    cur.execute("SELECT two_factor_secret FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()

    if row is None:
        return None
    return _decrypt_secret(row[0])


def verify_totp_token(username, token):
    _ensure_db_schema()
    if not token or not str(token).isdigit() or len(str(token)) != 6:
        return False

    secret = get_totp_secret(username)
    if not secret:
        return False

    totp = pyotp.TOTP(secret)
    return totp.verify(str(token).strip(), valid_window=1)


def is_two_factor_enabled(username):
    _ensure_db_schema()
    con = sql.connect(DATABASE_PATH)
    cur = con.cursor()
    cur.execute("SELECT two_factor_enabled FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()

    if row is None:
        return False
    return bool(row[0])


def enable_two_factor(username):
    _ensure_db_schema()
    con = sql.connect(DATABASE_PATH)
    cur = con.cursor()
    cur.execute(
        "UPDATE users SET two_factor_enabled = 1 WHERE username = ?",
        (username,),
    )
    con.commit()
    con.close()


def insertFeedback(feedback):
    _ensure_db_schema()
    con = sql.connect(DATABASE_PATH)
    cur = con.cursor()

    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    _ensure_db_schema()
    con = sql.connect(DATABASE_PATH)
    cur = con.cursor()

    data = cur.execute("SELECT feedback FROM feedback").fetchall()
    con.close()

    with open("templates/partials/success_feedback.html", "w", encoding="utf-8") as f:
        for row in data:
            safe_feedback = escape(str(row[0]), quote=True)
            f.write("<p>\n")
            f.write(f"{safe_feedback}\n")
            f.write("</p>\n")
