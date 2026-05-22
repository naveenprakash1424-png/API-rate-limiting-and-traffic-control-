from flask import Flask, render_template, request, redirect, flash, abort
import redis
import threading
import secrets
import smtplib
from email.mime.text import MIMEText
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import time, os 

app = Flask(__name__)

app.secret_key = "secretkey123##"

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

WINDOW = 60
FIXED_LIMIT = 100

MAX_TOKENS = 10
REFILL_RATE = 1  

BLOCK_TIME = 60 * 60 * 24 

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "naveenna242@gmail.com"
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")


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

# SIGNUP 
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # data = request.get_json()
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
        threading.Thread(
    target=send_email,
    args=(
        email,
        "Signup Successful!",
        f"""
Welcome {username}

Your account has been created successfully.

Email: {email}
Signup Time: {datetime.now()}

Thank you.
"""
    )
).start()
        return redirect("/login")

    return render_template("signup.html")



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

        attempts = r.get(fail_key)

        if attempts and int(attempts) >= LIMIT:
            flash("Too many wrong password attempts. Try again after 5 minutes")
            return redirect("/login")

        if not check_password_hash(user["password"], password):

            count = r.incr(fail_key)

            if count == 1:
                r.expire(fail_key, WINDOW)

            remaining = LIMIT - count

            flash(f"Wrong password. Remaining attempts: {remaining}")
            return redirect("/login")

        r.delete(fail_key)

        flash("Login successful")

        threading.Thread(target=send_email,
        args=(email,"Login Successful!", f"You are currently logged in successfully at {datetime.now()}")).start()

        return f"Welcome {user['username']}"

    return render_template("login.html")


#   FORGOT PASSWORD 
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"]

        user = r.hgetall(f"user:{email}")

        if not user:
            flash("Email not found! Please Enter correct Email...!")
            return redirect("/forgot")

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

        flash("Reset email sent..check You Inbox..!")
        return redirect("/login")

    return render_template("forgot.html")


#  RESET 
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
def rate_limiter():

    ip = request.remote_addr
    now = time.time()

    if r.get(f"blocked:{ip}"):
        abort(403)

    window_id = int(now) // WINDOW
    window_key = f"fw:{ip}:{window_id}"

    current = r.incr(window_key)

    if current == 1:
        r.expire(window_key, WINDOW)

    if current > FIXED_LIMIT:
        r.set(f"blocked:{ip}", "1", ex=BLOCK_TIME)
        abort(429)

    # =====================
    # 3. TOKEN BUCKET (SMOOTH CONTROL)
    # =====================
    bucket_key = f"tb:{ip}"

    data = r.hgetall(bucket_key)

    if not data:
        tokens = MAX_TOKENS
        last_refill = now
    else:
        tokens = float(data.get("tokens", MAX_TOKENS))
        last_refill = float(data.get("last_refill", now))

    elapsed = now - last_refill
    tokens = min(MAX_TOKENS, tokens + elapsed * REFILL_RATE)

    if tokens < 1:
        abort(429)

    tokens -= 1

    r.hset(bucket_key, mapping={
        "tokens": tokens,
        "last_refill": now
    })
#Error Handling

@app.errorhandler(429)
def too_many_requests(error):
    return render_template(
        "error.html",
        code=429,
        message="Too many requests. Please try again later."
    ), 429


@app.errorhandler(404)
def not_found(error):
    return render_template(
        "error.html",
        code=404,
        message="Page not found."
    ), 404


@app.errorhandler(500)
def server_error(error):
    return render_template(
        "error.html",
        code=500,
        message="Internal server error."
    ), 500


@app.errorhandler(403)
def forbidden(error):
    return render_template(
        "error.html",
        code=403,
        message="Access denied."
    ), 403


@app.errorhandler(Exception)
def handle_exception(error):
    if isinstance(error, HTTPException):
        return error
    return render_template(
        "error.html",
        code=500,
        message=str(error)
    ), 500

if __name__ == "__main__":
    app.run(debug=True)
