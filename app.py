from flask import Flask, render_template, request, redirect, url_for, flash
import redis
import threading
import secrets
import smtplib
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import time, os
app = Flask(__name__)
app.secret_key = "secret123"

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

MAX_TOKENS = 3
REFILL_RATE = 3

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "naveenna242@gmail.com"
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

#SENDING EMAILS
def send_email(receiver, subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = receiver

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)


@app.route("/")
def home():
    return redirect("/login")


# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        if r.exists(f"user:{email}"):
            flash("User already exists")
            return redirect("/signup")

        hashed = generate_password_hash(password)

        r.hset(
            f"user:{email}",
            mapping={
                "username": username,
                "email": email,
                "password": hashed
            }
        )

        flash("Signup successful")
        return redirect("/login")

    return render_template("signup.html")


# ---------------- LOGIN ----------------
LIMIT = 5
WINDOW = 300   # 5 minutes


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        fail_key = f"fail:{email}"

        user = r.hgetall(f"user:{email}")

        if not user:
            flash("User not found")
            return redirect("/login")

        # Check failed attempts
        attempts = r.get(fail_key)

        if attempts and int(attempts) >= LIMIT:
            flash("Too many wrong password attempts. Try again after 5 minutes")
            return redirect("/login")

        # Wrong password
        if not check_password_hash(user["password"], password):

            count = r.incr(fail_key)

            if count == 1:
                r.expire(fail_key, WINDOW)

            remaining = LIMIT - count

            flash(f"Wrong password. Remaining attempts: {remaining}")
            return redirect("/login")

        # Successful login → reset fail count
        r.delete(fail_key)

        flash("Login successful")

        send_email(
            email,
            "Login Successful!",
            f"You are currently logged in successfully at {datetime.now()}"
        )

        return f"Welcome {user['username']}"

    return render_template("login.html")


# ---------------- FORGOT PASSWORD ----------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"]

        user = r.hgetall(f"user:{email}")

        if not user:
            flash("Email not found! Please Signup")
            return redirect("/signup")

        token = secrets.token_urlsafe(32)
        r.setex(f"reset:{token}", 600, email)

        reset_link = f"http://localhost:5000/reset/{token}"

        body = f"""
Click link to reset password:

{reset_link}

Expires in 10 minutes.
"""

        threading.Thread(
            target=send_email,
            args=(email, "Reset Password", body)
        ).start()

        flash("Reset email sent")
        return redirect("/login")

    return render_template("forgot.html")


# ---------------- RESET ----------------
@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    email = r.get(f"reset:{token}")

    if not email:
        return "Invalid token"

    if request.method == "POST":
        password = request.form["password"]

        r.hset(
            f"user:{email}",
            "password",
            generate_password_hash(password)
        )

        r.delete(f"reset:{token}")

        flash("Password updated")
        return redirect("/login")

    return render_template("reset.html")


@app.before_request
def token_bucket():
    ip = request.remote_addr
    key = f"bucket:{ip}"

    data = r.hgetall(key)
    now = time.time()

    if not data:
        tokens = MAX_TOKENS
        last_refill = now
    else:
        tokens = float(data["tokens"])
        last_refill = float(data["last_refill"])

    # refill tokens
    elapsed = now - last_refill
    refill = elapsed * REFILL_RATE
    tokens = min(MAX_TOKENS, tokens + refill)

    if tokens < 1:
        return "Too many requests. Try later.", 429

    # consume token
    tokens -= 1

    r.hset(key, mapping={
        "tokens": tokens,
        "last_refill": now
    })

    r.expire(key, 120)
if __name__ == "__main__":
    app.run(debug=True, threaded=True)
