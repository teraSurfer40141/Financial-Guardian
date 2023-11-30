import os
import flask
from flask_session import Session
import sqlite3
from cs50 import SQL
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from functools import wraps

# Configure application
app = flask.Flask(__name__)

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if flask.session.get("user_id") is None:
            return flask.redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

db = SQL("sqlite:///database.db")

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

accountType = None

@app.route("/")
@login_required
def index():
    global accountType
    if accountType == "Guardian":
        pending = db.execute('SELECT * FROM request WHERE person_id = (?) AND status = "Pending"', flask.session["user_id"])
        username = db.execute("SELECT username FROM guardian_info WHERE id = (?)", flask.session["user_id"])[0]["username"]
        number = len(pending)
        return flask.render_template("main.html", number=number,username=username,accountType=accountType)
    elif accountType == "Ward":
        number = int(db.execute("SELECT new_request FROM ward_info WHERE id = (?)", flask.session["user_id"])[0]["new_request"])
        username = db.execute("SELECT username FROM ward_info WHERE id = (?)", flask.session["user_id"])[0]["username"]
        return flask.render_template("main.html", number=number,username=username,accountType=accountType)

@app.route("/request", methods=["GET","POST"])
@login_required
def request():
    global accountType
    if flask.request.method == "GET":
        if accountType == "Ward":
            return flask.render_template("request.html")
        if accountType == "Guardian":
            requests = db.execute("SELECT * FROM request WHERE person_id = (?) AND status = (?)", flask.session["user_id"], "Pending")
            return flask.render_template("requested.html", requests=requests)
            
    if flask.request.method == "POST":
        if accountType == "Ward":
            item_name = flask.request.form.get("item_name")
            price = float(flask.request.form.get("price"))
            description = flask.request.form.get("description")
            reason_for_buying = flask.request.form.get("reason_for_buying")
            want_need = flask.request.form.get("want_need")
            url = flask.request.form.get("url")
            now = datetime.now()
            db.execute("INSERT INTO request (person_id, item_name, price_in_usd, description, reason_for_buying, want_need, status, date_time, url) VALUES (?,?,?,?,?,?,?,?,?)",flask.session["user_id"], item_name, price, description, reason_for_buying, want_need, "Pending", now.strftime("%y-%m-%d %H:%M:%S"), url)
            return flask.redirect("/request")
        if accountType == "Guardian":
            item_id = flask.request.form.get("id")
            status = flask.request.form.get("status")
            reason = flask.request.form.get("reason")
            db.execute("UPDATE request SET status = (?), reason_for_rejecting = (?) WHERE id = (?);", status, reason, item_id)
            number = int(db.execute("SELECT new_request FROM ward_info WHERE id = (?)",flask.session["user_id"])[0]["new_request"])
            number += 1
            db.execute("UPDATE ward_info SET new_request = (?) WHERE id = (?)", number, flask.session["user_id"])
            return flask.redirect("/request")
            

@app.route("/history", methods=["GET"])
@login_required
def history():
    requests = db.execute("SELECT * FROM request WHERE person_id = (?)", flask.session["user_id"])
    return flask.render_template("history.html", requests=requests)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    global accountType
    if accountType == "Ward":
        db.execute("UPDATE ward_info SET new_request = 0 WHERE id = (?)", flask.session["user_id"])
    accountType = None
    # Forget any user_id
    flask.session.clear()

    # Redirect user to login form
    return flask.redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    global accountType
    """Log user in"""
    if flask.request.method == "GET":
        return flask.render_template("login.html")

    # User reached route via POST (as by submitting a form via POST)
    if flask.request.method == "POST":
        flask.session.clear()


        # Ensure username was submitted
        if not flask.request.form.get("username"):
            return("Apologies, no username was inputted")

        # Ensure password was submitted
        elif not flask.request.form.get("password"):
            return("Apologies, no password was inputted")

        if flask.request.form.get("accountType") == "Ward":
            accountType = "Ward"
            # Query database for username
            rows = db.execute("SELECT * FROM ward_info WHERE username = ?", flask.request.form.get("username"))

            # Ensure username exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["hash"], flask.request.form.get("password")):
                return ("Apologies, invalid username or password")

            # Remember which user has logged in
            flask.session["user_id"] = rows[0]["id"]

            # Redirect user to home page
            return flask.redirect("/")

        if flask.request.form.get("accountType") == "Guardian":
            accountType = "Guardian"
            # Query database for username
            rows = db.execute("SELECT * FROM guardian_info WHERE username = ?", flask.request.form.get("username"))

            # Ensure username exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["hash"], flask.request.form.get("password")):
                return ("Apologies, invalid username or password")

            # Remember which user has logged in
            flask.session["user_id"] = rows[0]["id"]

            # Redirect user to home page
            return flask.redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    if flask.request.method == "GET":
        return flask.render_template("register.html")
    if flask.request.method == "POST":
        usernameWard = flask.request.form.get("usernameWard")
        passwordWard = flask.request.form.get("passwordWard")
        confirmationWard = flask.request.form.get("confirmationWard")
        existingWard = db.execute("SELECT username FROM ward_info")
        existing_usernameWard = []
        for user in existingWard:
            existing_usernameWard.append(user["username"])
        if usernameWard in existing_usernameWard:
            return("Apologies, the username of Ward you are trying to register already exist")
        elif passwordWard != confirmationWard:
            return("Apologies, the passwords of Ward do not match")
        elif not flask.request.form.get("usernameWard"):
            return("Apologies, the username of the ward was not provided")
        elif not flask.request.form.get("passwordWard"):
            return("Apologies, the password of the ward was not provided")
        else:
            hashedWard = generate_password_hash(passwordWard)
            db.execute("INSERT INTO ward_info (username, hash) VALUES (?,?)", usernameWard, hashedWard)
        idNo = db.execute("SELECT id FROM ward_info WHERE username = (?)", usernameWard)
        usernameGuardian = flask.request.form.get("usernameGuardian")
        passwordGuardian = flask.request.form.get("passwordGuardian")
        confirmationGuardian = flask.request.form.get("confirmationGuardian")
        existingGuardian = db.execute("SELECT username FROM guardian_info")
        existing_usernameGuardian = []
        for user in existingGuardian:
            existing_usernameGuardian.append(user["username"])
        if usernameGuardian in existing_usernameGuardian:
            return("Apologies, the username of Guardian you are trying to register already exist")
        elif passwordGuardian != confirmationGuardian:
            return("Apologies, the passwords of Guardian do not match")
        elif not flask.request.form.get("usernameGuardian"):
            return("Apologies, the username of the Guardian was not provided")
        elif not flask.request.form.get("passwordGuardian"):
            return("Apologies, the password of the Guardian was not provided")
        else:
            hashedGuardian = generate_password_hash(passwordGuardian)
            db.execute("INSERT INTO guardian_info (ward_id, username, hash) VALUES (?,?,?)", idNo, usernameGuardian, hashedGuardian)