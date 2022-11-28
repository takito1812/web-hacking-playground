#!/usr/bin/env python3

"""Socially App"""

import datetime
from functools import wraps
import re
import os
import smtplib
import random
import jwt
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    render_template_string,
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

app.secret_key = os.urandom(24)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "socially.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["JWT_SECRET_KEY"] = os.urandom(24)

app.config["SESSION_COOKIE_HTTPONLY"] = False

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

ISS = "socially-app"

EMAIL = "support@socially"

db = SQLAlchemy(app)


class User(db.Model):
    """User model"""

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    admin = db.Column(db.Boolean, default=False)
    otp_enabled = db.Column(db.Boolean, default=False)
    otp_code = db.Column(db.String(6), nullable=False, default="000000")

    def __repr__(self):
        return f"<User {self.username}>"


class Post(db.Model):
    """Post model"""

    id = db.Column(db.Integer, primary_key=True)
    post = db.Column(db.String(120), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("posts", lazy=True))

    def __repr__(self):
        return f"<Post {self.post}>"


class Settings(db.Model):
    """Settings model"""

    id = db.Column(db.Integer, primary_key=True)
    setting = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.String(80), nullable=False)


db.create_all()


def token_required(func):
    """Token required decorator"""

    @wraps(func)
    def decorator(*args, **kwargs):
        if request.headers.get("Authorization"):
            try:
                token = request.headers.get("Authorization").split()[1]
            except IndexError:
                return jsonify({"error": "Cannot decode token"}), 401
            try:
                data = jwt.decode(
                    token,
                    app.config["JWT_SECRET_KEY"],
                    algorithms=["HS256"],
                    options={"verify_signature": False},
                )
                if data["iss"] != ISS:
                    return jsonify({"error": "Invalid token"}), 401
            except jwt.DecodeError:
                return jsonify({"error": "Invalid token"}), 401
            user = User.query.filter_by(id=data["id"]).first()
            if not user:
                return jsonify({"error": "User not found"}), 401
            return func(user, *args, **kwargs)
        return jsonify({"error": "Missing token"}), 401

    return decorator


def session_required(func):
    """Session required decorator"""

    @wraps(func)
    def decorator(*args, **kwargs):
        if not session:
            return jsonify({"error": "Session cookie not found"}), 401
        return func(*args, **kwargs)

    return decorator


def otp_required(func):
    """OTP required decorator"""

    @wraps(func)
    def decorator(*args, **kwargs):
        if session.get("otp_verified") is False and request.remote_addr != "127.0.0.1":
            return jsonify({"error": "OTP not verified"}), 401
        return func(*args, **kwargs)

    return decorator


def admin_required(func):
    """Admin required decorator"""

    @wraps(func)
    def decorator(*args, **kwargs):
        if not session.get("admin"):
            return jsonify({"error": "Admin privileges required"}), 401
        return func(*args, **kwargs)

    return decorator


@app.route("/")
def index():
    """Index page"""
    if request.args.get("next"):
        url = request.args.get("next")
        if re.search("javascript", url, re.IGNORECASE) or re.search(
            "alert[(`].*[)`]", url, re.IGNORECASE
        ):
            return render_template("waf.html")
        return render_template("next.html", url=url)
    return render_template(
        "index.html", posts=sorted(Post.query.all(), key=lambda x: x.date, reverse=True)
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page"""
    if request.method == "POST":
        user = User.query.filter_by(username=request.json["username"]).first()
        if user and check_password_hash(user.password, request.json["password"]):
            token = jwt.encode(
                {"iss": ISS, "id": user.id},
                app.config["JWT_SECRET_KEY"],
                algorithm="HS256",
            )
            return jsonify({"token": token})
        return jsonify({"error": "Invalid credentials"}), 401
    return render_template("login.html")


@app.route("/session")
@token_required
def session_info(user):
    """Get a session cookie"""
    session["username"] = user.username
    session["email"] = user.email
    if user.otp_enabled == 1:
        session["otp_verified"] = False
    if user.admin == 1:
        session["admin"] = True
    return jsonify({"success": "Session updated"})


@app.route("/post", methods=["POST"])
@session_required
def post():
    """Post a message"""
    if request.json.get("post"):
        return jsonify({"error": "Sorry, posting is disabled"}), 401
    return jsonify({"error": "Missing field"}), 401


@app.route("/logout")
def logout():
    """Logout page"""
    session.clear()
    return render_template("logout.html")


@app.route("/admin")
@session_required
@admin_required
def admin():
    """Admin page"""
    smtp_server = Settings.query.filter_by(setting="smtp_server").first()
    return render_template("admin.html", smtp_server=smtp_server)


@app.route("/updatesmtp", methods=["POST"])
@session_required
@admin_required
@otp_required
def updatesmtp():
    """Update SMTP server"""
    if request.json.get("smtpServer"):
        smtp_server = Settings.query.filter_by(setting="smtp_server").first()
        smtp_server.value = request.json["smtpServer"]
        db.session.commit()
        return jsonify({"success": "SMTP server updated successfully"}), 201
    return jsonify({"error": "Missing fields"}), 401


@app.route("/sendemail", methods=["POST"])
@session_required
@admin_required
@otp_required
def sendemail():
    """Send email"""
    if len(request.json["message"]) > 45:
        return jsonify({"error": "Message too long"}), 401
    try:
        smtp_server = Settings.query.filter_by(setting="smtp_server").first()
        server = smtplib.SMTP(smtp_server.value, 25)
        server.sendmail(
            EMAIL,
            request.json["to"],
            render_template_string(request.json["message"]),
        )
        server.quit()
    except ConnectionRefusedError:
        pass
    return jsonify({"success": "Email sent successfully"}), 201


@app.route("/generateotp")
@token_required
@session_required
def generateotp(user):
    """Generate OTP"""
    otp_code = str(random.randint(100000, 999999))
    db.session.query(User).filter(User.id == user.id).update({User.otp_code: otp_code})
    db.session.commit()
    try:
        smtp_server = Settings.query.filter_by(setting="smtp_server").first()
        server = smtplib.SMTP(smtp_server.value, 25)
        server.sendmail(
            EMAIL,
            user.email,
            render_template("otp.html", otp_code=otp_code, user=user),
        )
        server.quit()
    except ConnectionRefusedError:
        pass
    return jsonify({"success": "OTP generated successfully"}), 201


@app.route("/verifyotp")
@session_required
def verifyotp_page():
    """Verify OTP page"""
    return render_template("verifyotp.html")


@app.route("/verifyotp", methods=["POST"])
@token_required
@session_required
def verifyotp(user):
    """Verify OTP"""
    if request.json.get("otp") == user.otp_code:
        session["otp_verified"] = True
        session["username"] = user.username
        session["email"] = user.email
        return jsonify({"success": "OTP verified successfully"}), 201
    return jsonify({"error": "Invalid OTP"}), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
