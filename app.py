# app.py
import os
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, session, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import (DataRequired, Email, Length, Regexp, Optional)
from flask_bcrypt import Bcrypt
from sqlalchemy import text
import bleach

# ----------------- APP CONFIG -----------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-please-change")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Security/session settings -- for local testing you may set SESSION_COOKIE_SECURE=False
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=60)

# CSRF
app.config["WTF_CSRF_TIME_LIMIT"] = None

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# ----------------- MODELS -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # relationship:
    contacts = db.relationship("Contact", backref="owner", lazy="dynamic")


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    full_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(50), nullable=True)
    address = db.Column(db.String(300), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    dob = db.Column(db.String(50), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ----------------- FORMS & VALIDATION -----------------
NAME_RE = r"^[A-Za-z0-9 \-'\.,]+$"  # allow letters, numbers, spaces, common punctuation

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField("Password", validators=[DataRequired()])

class ContactForm(FlaskForm):
    full_name = StringField("Full name", validators=[
        DataRequired(), Length(max=200), Regexp(NAME_RE, message="Name contains invalid characters.")
    ])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=200)])
    phone = StringField("Phone", validators=[Optional(), Length(max=50)])
    address = StringField("Address", validators=[Optional(), Length(max=300)])
    city = StringField("City", validators=[Optional(), Length(max=100), Regexp(NAME_RE, message="City contains invalid characters.")])
    country = StringField("Country", validators=[Optional(), Length(max=100), Regexp(NAME_RE, message="Country contains invalid characters.")])
    dob = StringField("Date of Birth", validators=[Optional(), Length(max=50)])
    notes = TextAreaField("Notes", validators=[Optional(), Length(max=2000)])

# ----------------- HELPERS -----------------
def sanitize_html(text):
    allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li']
    return bleach.clean(text or "", tags=allowed_tags, strip=True)

def hash_password(raw):
    return bcrypt.generate_password_hash(raw).decode('utf-8')

def check_password_hash_safe(hashed, raw):
    return bcrypt.check_password_hash(hashed, raw)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper

@app.before_request
def make_session_permanent():
    session.permanent = True

# ----------------- ROUTES -----------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("contacts"))
    return render_template("index.html")

# ----- Auth -----
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return redirect(url_for("register"))
        user = User(username=username, password_hash=hash_password(password))
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash_safe(user.password_hash, password):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))
        session["user_id"] = user.id
        session["username"] = user.username
        flash(f"Welcome, {user.username}!", "success")
        nxt = request.args.get("next")
        return redirect(nxt or url_for("contacts"))
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

# ----- Contacts (owner-based) -----
@app.route("/contacts")
@login_required
def contacts():
    user_id = session.get("user_id")
    contacts = Contact.query.filter_by(owner_id=user_id).order_by(Contact.created_at.desc()).all()
    return render_template("contacts.html", contacts=contacts)

@app.route("/contacts/new", methods=["GET", "POST"])
@login_required
def new_contact():
    form = ContactForm()
    if form.validate_on_submit():
        notes_clean = sanitize_html(form.notes.data)
        contact = Contact(
            owner_id=session["user_id"],
            full_name=form.full_name.data.strip(),
            email=form.email.data.strip(),
            phone=form.phone.data.strip() if form.phone.data else None,
            address=form.address.data.strip() if form.address.data else None,
            city=form.city.data.strip() if form.city.data else None,
            country=form.country.data.strip() if form.country.data else None,
            dob=form.dob.data.strip() if form.dob.data else None,
            notes=notes_clean
        )
        db.session.add(contact)
        db.session.commit()
        flash("Contact added.", "success")
        return redirect(url_for("contacts"))
    return render_template("contact_form.html", form=form, contact=None)

@app.route("/contacts/<int:c_id>/edit", methods=["GET", "POST"])
@login_required
def edit_contact(c_id):
    contact = Contact.query.get_or_404(c_id)
    if contact.owner_id != session.get("user_id"):
        abort(403)
    form = ContactForm(obj=contact)
    if form.validate_on_submit():
        contact.full_name = form.full_name.data.strip()
        contact.email = form.email.data.strip()
        contact.phone = form.phone.data.strip() if form.phone.data else None
        contact.address = form.address.data.strip() if form.address.data else None
        contact.city = form.city.data.strip() if form.city.data else None
        contact.country = form.country.data.strip() if form.country.data else None
        contact.dob = form.dob.data.strip() if form.dob.data else None
        contact.notes = sanitize_html(form.notes.data)
        db.session.commit()
        flash("Contact updated.", "success")
        return redirect(url_for("contacts"))
    return render_template("contact_form.html", form=form, contact=contact)

@app.route("/contacts/<int:c_id>/delete", methods=["POST"])
@login_required
def delete_contact(c_id):
    contact = Contact.query.get_or_404(c_id)
    if contact.owner_id != session.get("user_id"):
        abort(403)
    db.session.delete(contact)
    db.session.commit()
    flash("Contact deleted.", "info")
    return redirect(url_for("contacts"))

# ----- Parameterized raw SQL example (safe) -----
@app.route("/search_by_email")
@login_required
def search_by_email():
    email = request.args.get("email", "", type=str).strip()
    if not email:
        flash("Provide ?email=... query param", "warning")
        return redirect(url_for("contacts"))
    # Safe parameterized query using sqlalchemy.text
    stmt = text("SELECT id, full_name, email FROM contact WHERE owner_id = :owner AND email = :email")
    rows = db.session.execute(stmt, {"owner": session["user_id"], "email": email}).fetchall()
    return render_template("search_results.html", results=rows, query=email)

# ----------------- ERROR HANDLERS -----------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error("Server error: %s", e)
    return render_template("500.html"), 500

# ----------------- RUN -----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
