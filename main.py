from flask import Flask, render_template, request, redirect, url_for, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from send_mail import SendMail
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = "gwrbebpomRbeok"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///user.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)

code, attempts = 0, 0
name, mc_name, email, contact = "", "", "", ""


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    contact = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(500), nullable=True)


# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        global name, mc_name, email, contact, code

        name = request.form["name"]
        mc_name = request.form["mc-name"]
        email = request.form["email"]
        contact = request.form["contact"]

        users = db.session.query(User).all()
        if users:
            user_emails = [user.email for user in users]
            if email in user_emails:
                flash("This email already exists")
                return redirect(url_for("sign_up"))

        send_mail = SendMail(email, name)
        code = send_mail.verify()

        return redirect(url_for("verify"))

    return render_template("sign-up.html", form=FlaskForm())


@app.route("/send-code")
def send_code():
    global code

    send_mail = SendMail(email, name)
    code = send_mail.verify()

    db.session.commit()

    return redirect(url_for("verify"))


def flush_values():
    global attempts, code, name, mc_name, email, contact

    attempts, code = 0, 0
    name, mc_name, email, contact = "", "", "", ""


def is_code_expired(function):
    def wrapper(*args, **kwargs):
        if email and code:
            function(*args, **kwargs)
        else:
            flash("Verification code has been expired. Try Signing up.")
            return redirect(url_for("sign_up"))
    return wrapper


@app.route("/Verify", methods=["GET", "POST"])
@is_code_expired
def verify():

    if request.method == "POST":
        global attempts

        user_code = int("".join([request.form[f"{num}"] for num in range(6)]))
        if not user_code == int(code):
            attempts += 1
            if attempts != 1 and attempts < 6:
                flash(f"Invalid code. {6-attempts} more attempts remaining...")
                return redirect(url_for("verify"))
            elif attempts >= 6:

                flush_values()
                flash("Verification Code Expired or your account already is set up.")
                return redirect(url_for("sign_up"))
            elif attempts == 1:
                flash("Invalid verification code")
                return redirect(url_for("verify"))
        else:
            user = User(
                name=name,
                username=mc_name,
                email=email,
                contact=contact
            )
            db.session.add(user)
            db.session.commit()

            flush_values()

            return redirect(url_for("home"))

    return render_template("verification.html", email=email, form=FlaskForm())


@app.route("/login/members", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        member_email = request.form["email"]
        password = request.form["pass"]

        user = User.query.filter_by(email=member_email).first()
        if user:
            if user.name == "Admin":
                correct_password = check_password_hash(
                    pwhash=user.password,
                    password=password
                )

                if correct_password:
                    login_user(user)
                    return redirect(url_for("dashboard"))
                else:
                    flash("Wrong password")
                    return redirect(url_for("login"))
            else:
                abort(403)
        else:
            flash("This email doesn't exist")
            return redirect(url_for("login"))

    return render_template("login.html", form=FlaskForm())


@app.route("/admin/dashboard")
@login_required
def dashboard():
    users = db.session.query(User).all()
    return render_template("dashboard.html", users=users)


@app.route("/create/admin")
def create_admin():
    user = User(
        name="Admin",
        username="Admin",
        contact="None",
        email="admin@gmail.com",
        password=generate_password_hash(
            password="elitesadmin123",
            salt_length=6
        )
    )

    db.session.add(user)
    db.session.commit()

    return "Admin created successfully..."


if __name__ == "__main__":
    app.run(debug=True)
