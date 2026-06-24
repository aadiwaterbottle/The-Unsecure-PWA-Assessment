import os
import sqlite3 as sql
import time
import random
import hashlib
import bcrypt
from html import escape


def _get_password_pepper():
    # Load the pepper strictly from the environment so it is never hardcoded.
    pepper = os.environ.get("PASSWORD_PEPPER")
    if not pepper:
        raise RuntimeError("PASSWORD_PEPPER environment variable is not set.")
    return pepper


def _apply_password_pepper(password):
    # Combine the password with a server-side pepper and hash it with SHA-256.
    # This avoids the cryptography dependency while still adding a secret pepper layer.
    pepper = _get_password_pepper().encode("utf-8")
    password_bytes = password.encode("utf-8")
    combined = password_bytes + b"|" + pepper
    return hashlib.sha256(combined).hexdigest()


def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Apply the server-side pepper before hashing with bcrypt.
    peppered_password = _apply_password_pepper(password)
    hashed_password = bcrypt.hashpw(
        peppered_password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")

    # Parameterized query prevents SQL injection.
    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth) VALUES (?, ?, ?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Parameterized query prevents SQL injection.
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    stored_user = cur.fetchone()

    if stored_user is None:
        con.close()
        return False
    else:
        stored_hash = stored_user[0]

        # Plain text log of visitor count as requested by Unsecure PWA management
        with open("visitor_log.txt", "r", encoding="utf-8") as file:
            number = int(file.read().strip())
            number += 1
        with open("visitor_log.txt", "w", encoding="utf-8") as file:
            file.write(str(number))

        # Simulate response time of heavy app for testing purposes
        time.sleep(random.randint(80, 90) / 1000)

        # Apply the same peppering logic during login and verify against the stored bcrypt hash.
        peppered_password = _apply_password_pepper(password)
        if bcrypt.checkpw(peppered_password.encode("utf-8"), stored_hash.encode("utf-8")):
            con.close()
            return True
        else:
            con.close()
            return False


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Parameterized query prevents SQL injection.
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Fetch feedback rows without interpolation.
    data = cur.execute("SELECT feedback FROM feedback").fetchall()
    con.close()

    # Escape user-supplied content before writing it into HTML to prevent XSS.
    with open("templates/partials/success_feedback.html", "w", encoding="utf-8") as f:
        for row in data:
            safe_feedback = escape(str(row[0]), quote=True)
            f.write("<p>\n")
            f.write(f"{safe_feedback}\n")
            f.write("</p>\n")
