import os
import secrets
from flask import Flask, g, render_template, request, redirect, session
from flask_cors import CORS
import user_management as dbHandler

# Code snippet for logging a message
# app.logger.critical("message")

app = Flask(__name__)

# Load the secret key strictly from the environment so sessions are not weak or hard-coded.
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY environment variable is not set.")

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") != "development",
    PROPAGATE_EXCEPTIONS=False,
)

# Disable cross-origin access by default to reduce the attack surface.
CORS(app, resources={r"/*": {"origins": []}})


def _get_or_create_csrf_token():
    # Create a per-session CSRF token.
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.before_request
def enforce_csrf():
    # Only protect state-changing requests.
    g.csrf_token = _get_or_create_csrf_token()
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if submitted_token != g.csrf_token:
            return ("Invalid or missing CSRF token.", 400)


@app.after_request
def add_security_headers(response):
    # Reduce caching of sensitive pages.
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(500)
def handle_errors(error):
    # Avoid leaking verbose error details to the client.
    return ("An unexpected error occurred.", error.code or 500)


@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back", csrf_token=g.csrf_token)
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back", csrf_token=g.csrf_token)


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB = request.form["dob"]
        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html", csrf_token=g.csrf_token)
    else:
        return render_template("/signup.html", csrf_token=g.csrf_token)


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Simple Dynamic menu
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    # Pass message to front end
    elif request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg, csrf_token=g.csrf_token)
    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            dbHandler.listFeedback()
            return render_template("/success.html", value=username, state=isLoggedIn, csrf_token=g.csrf_token)
        else:
            return render_template("/index.html", csrf_token=g.csrf_token)
    else:
        return render_template("/index.html", csrf_token=g.csrf_token)


if __name__ == "__main__":
    is_dev = os.environ.get("FLASK_ENV") == "development"
    app.config["TEMPLATES_AUTO_RELOAD"] = is_dev
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=is_dev, host="0.0.0.0", port=5000)
