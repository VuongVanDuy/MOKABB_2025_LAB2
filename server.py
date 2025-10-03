import os, re, secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "changeme")

def require_auth():
    return session.get("authorized") is True

def new_csrf():
    token = secrets.token_urlsafe(24)
    session["csrf"] = token
    return token

def check_csrf(token):
    return token and session.get("csrf") and secrets.compare_digest(token, session["csrf"])

def validate_form(data):
    errors = []
    for field, label in [("full_name", "Full Name"), ("email", "Email"),
                         ("scope", "Scope"), ("purpose", "Purpose"), ("agree", "Confirmation")]:
        if not data.get(field):
            errors.append(f"missing {label}")
    if data.get("email") and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", data["email"]):
        errors.append("invalid email")
    if data.get("expires"):
        try:
            datetime.strptime(data["expires"], "%Y-%m-%d")
        except ValueError:
            errors.append("invalid expiration date (yyyy-mm-dd)")
    return errors

@app.route("/")
def home():
    return redirect(url_for("authorize_form") if require_auth() else url_for("gate"))

@app.route("/gate", methods=["GET", "POST"])
def gate():
    if request.method == "GET":
        return render_template("gate.html", csrf=new_csrf())

    if not check_csrf(request.form.get("csrf")):
        flash("Invalid session. Try again.")
        return render_template("gate.html", csrf=new_csrf()), 400

    if request.form.get("password") == AUTH_PASSWORD:
        session["authorized"] = True
        return redirect(url_for("authorize_form"))
    else:
        flash("Wrong password.")
        return render_template("gate.html", csrf=new_csrf()), 401

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("gate"))

@app.route("/authorize", methods=["GET", "POST"])
def authorize_form():
    if not require_auth():
        return redirect(url_for("gate"))

    if request.method == "GET":
        return render_template("form.html", form={}, errors=None, success=False, csrf=new_csrf())

    if not check_csrf(request.form.get("csrf")):
        return "Invalid CSRF token", 400

    form = {
        "full_name": request.form.get("full_name", "").strip(),
        "email": request.form.get("email", "").strip(),
        "org": request.form.get("org", "").strip(),
        "scope": request.form.get("scope", "").strip(),
        "expires": request.form.get("expires", "").strip(),
        "purpose": request.form.get("purpose", "").strip(),
        "agree": request.form.get("agree") == "1",
    }
    errors = validate_form(form)
    if errors:
        return render_template("form.html", form=form, errors=errors, success=False, csrf=new_csrf()), 400

    payload = form.copy()
    return render_template(
        "form.html",
        success=True,
        submitted_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        payload=payload,
        form={}, errors=None, csrf=new_csrf()
    )

if __name__ == "__main__":
    app.run(debug=True)
