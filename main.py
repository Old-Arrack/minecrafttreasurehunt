from flask import Flask, render_template, request, redirect, url_for, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from send_mail import SendMail
import os
# This is a comment
app = Flask(__name__)

app.config['SECRET_KEY'] = "gwrbebpomRbeok"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///user.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)

code, attempts = 0, 0
name, mc_name, email, contact = "", "", "", ""


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    contact = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(500), nullable=True)


class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250))
    comment = db.Column(db.String(750), nullable=False)
    rate = db.Column(db.Integer)


db.create_all()


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
            user_emails = [u.email for u in users]
            username = [u.username for u in users]
            if email in user_emails:
                flash("This email already exists")
                return redirect(url_for("sign_up"))
            elif mc_name in username:
                flash("This account already exists.")
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


@app.route("/Verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        global attempts
        user_code = int("".join([request.form[f"{num}"] for num in range(6)]))
        if not user_code == int(code):
            attempts += 1
            if attempts != 1 and attempts < 6:
                flash(f"Invalid code. {6 - attempts} more attempts remaining...")
                return redirect(url_for("verify"))
            elif attempts >= 6:

                flush_values()
                flash("Verification Code Expired. Try signing up again.")
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

            flash("Account created")
            return redirect(url_for("home"))

    if email and code:
        return render_template("verification.html", email=email, form=FlaskForm())
    else:
        flash("Your verification code has been expired or your account is already set up.")
        return redirect(url_for("sign_up"))


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
        username="mcth_admin",
        contact="0123456789",
        email="elites@gmail.com",
        password=generate_password_hash(
            password="elitesadmin123",
            salt_length=6
        )
    )

    db.session.add(user)
    db.session.commit()

    return "Admin created successfully..."


@app.route("/log-out")
@login_required
def log_out():
    logout_user()
    return redirect(url_for("home"))


@app.route("/settings/<username>", methods=["GET", "POST"])
@login_required
def settings(username):
    selected_user = User.query.filter_by(username=username).first()
    return render_template("settings.html", user=selected_user, form=FlaskForm())


@app.route("/change-details/<user_email>", methods=["POST"])
@login_required
def change_details(user_email):
    if request.method == "POST":
        user = User.query.filter_by(email=user_email).first()

        all_users = db.session.query(User).all()
        usernames = [u.username for u in all_users if u.name != user.name]
        emails = [u.email for u in all_users if u.name != user.name]

        new_username = request.form["username"]
        new_email = request.form["email"]

        if new_email in emails:
            flash("This email already exists.")
        elif new_username in usernames:
            flash("This mc username already exists.")
        else:
            user.name = request.form["name"]
            user.contact = request.form["contact"]
            user.username = new_username
            user.email = new_email

            db.session.commit()

        return redirect(url_for("settings", username=user.username))


@app.route("/delete/<user_email>", methods=["POST"])
@login_required
def delete(user_email):
    if request.method == "POST":
        user = User.query.filter_by(email=user_email).first()
        db.session.delete(user)
        db.session.commit()

        return redirect(url_for("dashboard"))


@app.route("/password/<user_email>", methods=["POST"])
@login_required
def change_password(user_email):
    if request.method == "POST":
        user = User.query.filter_by(email=user_email).first()
        current_pass = request.form["pass"]
        new_pass = request.form["new_pass"]
        confirm_pass = request.form["confirm_pass"]

        check_pass = check_password_hash(
            password=current_pass,
            pwhash=user.password
        )
        if check_pass:
            print("Works")
            if new_pass == confirm_pass:
                print("Works23")
                user.password = generate_password_hash(
                    password=new_pass,
                    salt_length=6
                )
                db.session.commit()
                flash("Password changed successfully.")
            else:
                flash("Passwords doesn't match.")
        else:
            flash("Invalid password.")

        return redirect(url_for("settings", username=user.username))


if __name__ == "__main__":
    app.run(debug=True)
