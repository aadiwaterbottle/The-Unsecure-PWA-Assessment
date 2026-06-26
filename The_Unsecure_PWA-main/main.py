import base64
import logging
import os
import secrets
import time
from io import BytesIO

import pyotp
import qrcode
from flask import Flask, g, redirect, render_template, request, session
from flask_cors import CORS

import user_management as db_handler

app = Flask(__name__)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

secret_key = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    secret_key = secrets.token_hex(32)
    logger.warning("SECRET_KEY not set; generated a temporary key for this process.")

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true",
    SESSION_COOKIE_NAME="session",
    PROPAGATE_EXCEPTIONS=False,
)

CORS(app, resources={r"/*": {"origins": []}})

SESSION_IDLE_TIMEOUT_SECONDS = 15 * 60
SESSION_ABSOLUTE_TIMEOUT_SECONDS = 24 * 60 * 60


def _get_or_create_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _clear_session(response=None):
    session.clear()
    session.modified = True
    if response is not None:
        response.delete_cookie(
            app.config.get("SESSION_COOKIE_NAME", "session"),
            path="/",
            httponly=True,
            secure=app.config["SESSION_COOKIE_SECURE"],
            samesite="Strict",
        )
    return response


def _start_pre_auth_session(username):
    session.clear()
    session["session_id"] = secrets.token_urlsafe(32)
    session["username"] = username
    session["auth_stage"] = "pending_2fa"
    session["authenticated"] = False
    session["created_at"] = time.time()
    session["last_activity"] = time.time()
    session.modified = True


def _start_authenticated_session(username):
    session.clear()
    session["session_id"] = secrets.token_urlsafe(32)
    session["username"] = username
    session["auth_stage"] = "authenticated"
    session["authenticated"] = True
    session["created_at"] = time.time()
    session["last_activity"] = time.time()
    session.modified = True


def _session_is_expired():
    created_at = session.get("created_at")
    last_activity = session.get("last_activity")
    now = time.time()

    if created_at and (now - float(created_at) > SESSION_ABSOLUTE_TIMEOUT_SECONDS):
        return True
    if last_activity and (now - float(last_activity) > SESSION_IDLE_TIMEOUT_SECONDS):
        return True
    return False


def _touch_session():
    if session.get("username") or session.get("authenticated"):
        session["last_activity"] = time.time()
        session.modified = True


def _build_qr_code_data_url(otpauth_uri):
    img = qrcode.make(otpauth_uri)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _get_or_create_totp_setup(username):
    secret = db_handler.get_totp_secret(username)
    if not secret:
        secret, otpauth_uri = db_handler.create_totp_secret(username)
    else:
        totp = pyotp.TOTP(secret)
        otpauth_uri = totp.provisioning_uri(
            name=username,
            issuer_name="The Unsecure PWA",
        )
    return secret, otpauth_uri


@app.before_request
def enforce_csrf_and_session():
    g.csrf_token = _get_or_create_csrf_token()

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if submitted_token != g.csrf_token:
            return ("Invalid or missing CSRF token.", 400)

    if session.get("username") or session.get("authenticated") or session.get("auth_stage"):
        if _session_is_expired():
            logger.info("Expired session invalidated")
            _clear_session()
        else:
            _touch_session()

    g.state = bool(session.get("authenticated"))
    g.username = session.get("username")


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(500)
def handle_errors(error):
    return ("An unexpected error occurred.", error.code or 500)


@app.route("/logout")
def logout():
    response = redirect("/index.html?msg=You+have+been+logged+out.")
    _clear_session(response)
    return response


@app.route("/2fa/setup", methods=["GET", "POST"])
def two_factor_setup():
    if session.get("authenticated"):
        return redirect("/success.html")

    if not session.get("username") or session.get("auth_stage") != "pending_2fa":
        return redirect("/index.html?msg=Please+log+in+to+continue.")

    if request.method == "GET":
        _, otpauth_uri = _get_or_create_totp_setup(session["username"])
        qr_code_data_url = _build_qr_code_data_url(otpauth_uri)
        return render_template(
            "2fa.html",
            mode="setup",
            qr_code_data_url=qr_code_data_url,
            otpauth_uri=otpauth_uri,
            csrf_token=g.csrf_token,
            state=g.state,
            error="",
        )

    token = request.form.get("totp_token", "").strip()
    if db_handler.verify_totp_token(session["username"], token):
        db_handler.enable_two_factor(session["username"])
        _start_authenticated_session(session["username"])
        logger.info("2FA setup completed successfully")
        return redirect("/success.html")

    logger.warning("Failed 2FA setup verification")
    _, otpauth_uri = _get_or_create_totp_setup(session["username"])
    qr_code_data_url = _build_qr_code_data_url(otpauth_uri)
    return render_template(
        "2fa.html",
        mode="setup",
        qr_code_data_url=qr_code_data_url,
        otpauth_uri=otpauth_uri,
        csrf_token=g.csrf_token,
        state=g.state,
        error="Invalid verification code. Please try again.",
    )


@app.route("/2fa/verify", methods=["GET", "POST"])
def two_factor_verify():
    if session.get("authenticated"):
        return redirect("/success.html")

    if not session.get("username") or session.get("auth_stage") != "pending_2fa":
        return redirect("/index.html?msg=Please+log+in+to+continue.")

    if request.method == "GET":
        return render_template(
            "2fa.html",
            mode="verify",
            qr_code_data_url="",
            otpauth_uri="",
            csrf_token=g.csrf_token,
            state=g.state,
            error="",
        )

    token = request.form.get("totp_token", "").strip()
    if db_handler.verify_totp_token(session["username"], token):
        _start_authenticated_session(session["username"])
        logger.info("2FA verification succeeded")
        return redirect("/success.html")

    logger.warning("Failed 2FA verification attempt")
    return render_template(
        "2fa.html",
        mode="verify",
        qr_code_data_url="",
        otpauth_uri="",
        csrf_token=g.csrf_token,
        state=g.state,
        error="Invalid verification code. Please try again.",
    )


@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if not session.get("authenticated"):
        return redirect("/index.html?msg=Please+log+in+to+continue.")

    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)

    if request.method == "POST":
        feedback = request.form.get("feedback", "")
        db_handler.insertFeedback(feedback)
        db_handler.listFeedback()
        return render_template(
            "success.html",
            state=True,
            value=session["username"],
            csrf_token=g.csrf_token,
        )

    db_handler.listFeedback()
    return render_template(
        "success.html",
        state=True,
        value=session["username"],
        csrf_token=g.csrf_token,
    )


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        DoB = request.form.get("dob", "")
        db_handler.insertUser(username, password, DoB)
        return redirect("/index.html?msg=Account+created.+Please+log+in+to+complete+2FA+setup.")

    return render_template("signup.html", csrf_token=g.csrf_token, state=g.state)


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)

    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("index.html", msg=msg, csrf_token=g.csrf_token, state=g.state)

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if db_handler.authenticate_user(username, password):
            if db_handler.is_two_factor_enabled(username):
                _start_pre_auth_session(username)
                return redirect("/2fa/verify")
            _start_pre_auth_session(username)
            return redirect("/2fa/setup")

        return render_template(
            "index.html",
            msg="Invalid username or password",
            csrf_token=g.csrf_token,
            state=g.state,
        )

    return render_template("index.html", csrf_token=g.csrf_token, state=g.state)


if __name__ == "__main__":
    is_dev = os.environ.get("FLASK_ENV") == "development"
    app.config["TEMPLATES_AUTO_RELOAD"] = is_dev
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=is_dev, host="0.0.0.0", port=5000)
