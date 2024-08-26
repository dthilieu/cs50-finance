import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime


from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks including:
    user's symbol, shares, current price, total value, current cash, grand total"""

    # Get information of current user's buy stocks (include symbol and shares)
    stocks = db.execute(
        "SELECT symbol, SUM(shares) shares FROM transactions WHERE user_id = ? GROUP BY symbol",
        session["user_id"])

    # Total of all stocks value
    stocks_value = 0

    # Loop through each stock
    for stock in stocks:

        if stock["shares"] > 0:

            # Get current price
            current_price = lookup(stock["symbol"])["price"]

            # Update price with current price
            stock["price"] = usd(current_price)

            # Add total_value in stock dictcheck50 cs50/problems/2024/x/finance
            stock["total_value"] = usd(stock["shares"] * current_price)

            # Update stocks total value
            stocks_value += stock["shares"] * current_price

    # Get user's current cash
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    return render_template("index.html", stocks=stocks, cash=usd(cash), grand_total=usd(stocks_value + cash))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validate name and password
        if not username and not password:
            return apology("Missing Username and Password")
        if not username:
            return apology("Missing Username")
        if not password:
            return apology("Missing Password")

        # Validate password confirmation
        if not confirmation:
            return apology("Missing Password Confirmation")
        if password != confirmation:
            return apology("The passwords do not match")

        # Check if the username already exists
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                       username, generate_password_hash(password))
        except ValueError:
            return apology("The username already exists")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Record flash message
        flash("Register!")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Record flash message
        flash("Log In!")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user's password."""

    # User reached route via POST (as by clicking a link or via redirect)
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Validate current_password
        if not current_password:
            return apology("Missing Current Password")

        # Validate new_password
        if not new_password:
            return apology("Missing New Password")

        # Validate password confirmation
        if not confirmation:
            return apology("Missing Password Confirmation")
        if new_password != confirmation:
            return apology("The passwords do not match")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE id = ?", session["user_id"],
        )

        # Ensure username exists and password is correct
        if len(rows) != 1:
            return apology("invalid username", 403)
        elif not check_password_hash(rows[0]["hash"], current_password):
            return apology("invalid password", 403)

        # Update password
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?",
            generate_password_hash(new_password), rows[0]["id"]
        )

        # Record flash message
        flash("Password Changed!")

        # Redirect to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("change_password.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by clicking a link or via redirect)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        # Validate symbol
        if not symbol.isalpha():
            return apology("Symbol has to be alphabet")

        stock_quote = lookup(symbol)
        # Validate if symbol exist
        if stock_quote == None:
            return apology("Incorrect Symbol")

        return render_template("quoted.html", stock_name=stock_quote["symbol"], stock_price=usd(stock_quote["price"]))

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST from home page (as by clicking a link or via redirect)
    if request.method == "POST" and request.form.get("shortcut") == "shortcut":
        symbol = request.form.get("symbol")
        return render_template("buy.html", symbol=symbol)

    # User reached route via POST (as by clicking a link or via redirect)
    elif request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock_quote = lookup(symbol)

        # Validate symbol
        if not symbol:
            return apology("Missing Symbol")
        if not symbol.isalpha():
            return apology("Symbol has to be alphabet")
        if stock_quote == None:
            return apology("Incorrect Symbol")

        # Validate shares
        if not shares:
            return apology("Missing shares")
        # Validate shares if positive
        try:
            if int(shares) < 1:
                return apology("Shares minimum value is 1")
        except ValueError:
            return apology("Shares must be an integer")

        # Check user's available cash
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        # Check total price of the buying request
        price = stock_quote["price"]
        total_price = price * int(shares)

        # Get current date and time
        now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        # Compare user_cash and total_price, if susficient => proceed to buy
        if user_cash >= total_price:
            # Update transactions table
            db.execute("INSERT INTO transactions (user_id, symbol, price, shares, time) VALUES (?, ?, ?, ?, ?)",
                       session["user_id"], stock_quote["symbol"], price, shares, now)

            # Update cash in user account
            remaininng_cash = user_cash - total_price
            db.execute("UPDATE users SET cash = ? WHERE id = ?",
                       remaininng_cash, session["user_id"])

            # Record flash message
            flash("Bought!")

            return redirect("/")

        # If not, proceed to apology
        else:
            return apology("Not enough cash in your account")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST from home page (as by clicking a link or via redirect)
    if request.method == "POST" and request.form.get("shortcut") == "shortcut":
        symbol = request.form.get("symbol")
        return render_template("sell.html", symbol=symbol)

    # User reached route via POST (as by clicking a link or via redirect)
    elif request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        stock_quote = lookup(symbol)

        # Validate symbol and shares
        if not symbol and not shares:
            return apology("Missing Symbol and Shares")

        # Validate symbol
        if not symbol:
            return apology("Missing Symbol")
        if not symbol.isalpha():
            return apology("Symbol has to be alphabet")
        if stock_quote == None:
            return apology("Incorrect Symbol")

        # Validate shares
        if not shares:
            return apology("Missing Shares")

        # Validate shares if positive
        try:
            if int(shares) < 1:
                return apology("Shares minimum value is 1")
        except ValueError:
            return apology("Shares must be an integer")

        # Get information of user's shares with this symbol (include symbol and shares)
        stock = db.execute(
            "SELECT symbol, SUM(shares) shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol",
            session["user_id"], symbol)[0]

        # Check if user still own any shares of this stock
        if stock["shares"] == 0:
            return apology("You do not have this stock in your portfolio")

        # Check if user has enough shares to sell
        elif stock["shares"] < int(shares):
            return apology("You do not have enough shares")

        # If have enough shares, proceed to sell
        # Get current date and time
        now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        # Update transactions table
        db.execute("INSERT INTO transactions (user_id, symbol, price, shares, time) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], symbol, stock_quote["price"], -int(shares), now)

        # Update user's cash
        total_sell = stock_quote["price"] * int(shares)
        cash = db.execute("SELECT cash FROM users WHERE id = ?",
                          session["user_id"])[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   cash + total_sell, session["user_id"])

        # Record flash message
        flash("Sold!")

        # Redirect to homepage
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:

        # Get a list of symbol that user owns from database
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? AND shares > 0 GROUP BY symbol",
                             session["user_id"])
        return render_template("sell.html", symbols=symbols)


@app.route("/history")
@login_required
def history():
    """Show history of transactions:
    transaction type, symbol, price, shares, time"""

    # Get all transactions infor
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id = ?", session["user_id"])

    # Format price as usd
    for transaction in transactions:
        transaction["price"] = usd(transaction["price"])

    return render_template("history.html", transactions=transactions)
