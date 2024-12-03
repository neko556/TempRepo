from flask import Flask, request,render_template, flash, redirect, url_for, session, jsonify
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, IntegerField, EmailField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import timeago
from datetime import datetime, timedelta
import plotly.graph_objects as go
import os
import pdfplumber
import re
import tabula
import pandas as pd
from datetime import datetime as dt
import logging
import random
from decimal import Decimal


app = Flask(__name__, static_url_path='/static',
           )
app.config.from_pyfile('config.py')
UPLOAD_FOLDER = 'uploads/'  # Make sure this directory exists
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
mysql = MySQL(app)
class TransactionForm(Form):
    amount = IntegerField('Amount', [validators.NumberRange(min=1, max=1000000)])
    category = StringField('Category', [validators.Length(min=1, max=200)])
    date = StringField('Date', [validators.Length(min=1, max=200)])
    description = StringField('Description', [validators.Length(min=1, max=200)])

class SignUpForm(Form):
    first_name = StringField('First Name', [validators.Length(min=1, max=100)])
    last_name = StringField('Last Name', [validators.Length(min=1, max=100)])
    email = EmailField('Email address', [validators.DataRequired(), validators.Email()])
    username = StringField('Username', [validators.Length(min=4, max=100)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=100)])
    password = PasswordField('Password', [validators.DataRequired()])




def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Please login', 'info')
            return redirect(url_for('login'))
    return wrap

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
@is_logged_in
def about():
    return render_template('about.html')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'logged_in' in session:
        flash('You are already logged in', 'info')
        return redirect(url_for('addTransactions'))

    form = SignUpForm(request.form)
    if request.method == 'POST' and form.validate():
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        with mysql.connection.cursor() as cur:
            # Check if email already exists
            result = cur.execute("SELECT * FROM users WHERE email=%s", [email])
            if result > 0:
                flash('The entered email address has already been taken. Please try using or creating another one.', 'info')
                return redirect(url_for('signup'))

            # Check if username already exists
            result = cur.execute("SELECT * FROM users WHERE username=%s", [username])
            if result > 0:
                flash('The entered username has already been taken. Please try using another one.', 'info')
                return redirect(url_for('signup'))

            # Insert the new user into the database
            cur.execute("INSERT INTO users(first_name, last_name, email, username, password) VALUES(%s, %s, %s, %s, %s)",
                        (first_name, last_name, email, username, password))
            mysql.connection.commit()
            flash('You are now registered and can log in', 'success')
            return redirect(url_for('login'))

    return render_template('signUp.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        flash('You are already logged in', 'info')
        return redirect(url_for('addTransactions'))

    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password_input = form.password.data

        with mysql.connection.cursor() as cur:
            result = cur.execute("SELECT * FROM users WHERE username = %s", [username])
            if result > 0:
                data = cur.fetchone()
                password = data['password']
                if sha256_crypt.verify(password_input, password):
                    session['logged_in'] = True
                    session['username'] = username
                    session['userID'] = data['id']
                    flash('You are now logged in', 'success')
                    return redirect(url_for('addTransactions'))
                else:
                    error = 'Invalid Password'
                    return render_template('login.html', form=form, error=error)
            else:
                error = 'Username not found'
                return render_template('login.html', form=form, error=error)

    return render_template('login.html', form=form)

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


def extract_withdrawal_transactions(file_path):
    transactions = []

    try:
        # Use tabula to extract tables from the PDF
        dfs = tabula.read_pdf(file_path, pages='all', stream=True)

        for df in dfs:
            for index, row in df.iterrows():
                print(f"Processing row {index}: {row}")  # Debugging output

                if len(row) > 4:  # Ensure there are enough columns in the row
                    transaction_type = str(row[1] ) # Assuming UPI/DR or similar is in the second column

                    # Check if this is a withdrawal transaction
                    if is_withdrawal_transaction(transaction_type):
                        try:
                            # Extract date and amount from relevant columns
                            date_str = str(row[0]).strip()  # Assuming date is in the first column
                            amount_str = str(row[4]).replace(",", "").strip()  # Assuming amount is in the fifth column

                            # Debugging output for extracted values
                            print(f"Extracted date: '{date_str}', amount: '{amount_str}'")

                            # Check if date or amount fields are empty
                            if not date_str or not amount_str:
                                print(f"Skipping due to empty date or amount: {row}")
                                continue

                            # Convert date and amount
                            transaction_date = dt.strptime(date_str, "%d-%m-%Y").date()
                            amount = float(amount_str)

                            # Ignore zero or invalid amounts
                            if amount <= 0:
                                print(f"Skipping non-positive amount transaction: {row}")
                                continue

                            description = f"{row[1]} {row[2]} {row[3]} {row[4]}"  # Example: UPI/DR/430338962826/P
                            
                            # Optionally, you can concatenate more columns if needed
                            if len(row) > 5:
                                description += f" {row[5]} {row[6]} {row[7]}"  # Example: ARUNA/BKID/862818210002529/A
                            if len(row) > 8:
                                description += f" {row[8]} {row[9]}"  # Add more rows here if needed
                            if len(row) > 10:
                                description += f" {row[10]} {row[11]}"  # Add more rows here if needed
                            if len(row) > 12:
                                description += f" {row[12]}"  # Add more rows here if needed
                            # Continue adding as necessary

                            print(f"Description: {description}")  

                            # Add the withdrawal transaction to the list
                            transactions.append({
                                "date": transaction_date,
                                "description": description,
                                "amount": amount,
                                "category": infer_category(description)  # This function can be expanded as needed
                            })

                        except ValueError as ve:
                            print(f"Skipping invalid line due to parsing error: {row} - {ve}")
                            continue

            print(f"Total transactions extracted: {len(transactions)}")

    except Exception as e:
        print(f"Error reading PDF with tabula: {e}")

    return transactions

def is_withdrawal_transaction(transaction_type):
    """
    Determine if the transaction type indicates a withdrawal.
    This function can be expanded with more rules as needed.
    """
    withdrawal_keywords = ["UPI/DR", "Withdrawal", "Debit", "Transfer"]
    return any(keyword in transaction_type for keyword in withdrawal_keywords)
def infer_category(description):
    description = description.lower()

    # Check for Grocery-related keywords
    if any(keyword in description for keyword in ["grocery", "supermarket", "zepto", "blinkit", "jiomart", "bigbasket", "kiranakart"]):
        return "Grocery"
    
    # Check for Fuel-related keywords
    elif any(keyword in description for keyword in ["fuel", "hp", "bharatpetroleum", "indianoil", "hpcl", "iocl", "bpcl", "bp"]):
        return "Fuel"
    
    # Check for Food-related keywords
    elif any(keyword in description for keyword in ["restaurant", "food", "dine", "eat", "hotel", "cafe", "bar", "pub", "kfc", "pizzahut", "dominos", "burgerking"]):
        return "Food"
    
    # Check for Travel-related keywords
    elif any(keyword in description for keyword in ["travel", "flight", "air", "train", "bus"]):
        return "Travel"
    
    # Check for Movie-related keywords
    elif "bookmyshow" in description:
        return "Movies"
    
    # Check for online shopping keywords
    elif "amazon" in description:
        return "Amazon"
    elif "flipkart" in description:
        return "Flipkart"
    elif "myntra" in description:
        return "Myntra"
    
    # Check for payment or wallet keywords
    elif "paytm" in description:
        return "Paytm"
    elif "zomato" in description:
        return "Zomato"
    elif "uber" in description:
        return "Uber"
    elif "olacabs" in description:
        return "Ola"
    elif "swiggy" in description:
        return "Swiggy"
    elif "dunzo" in description:
        return "Dunzo"
    
    # Check for Pharmacy-related keywords
    elif "medplus" in description:
        return "Medplus"
    elif "apollo" in description:
        return "Apollo"
    elif "pharmacy" in description:
        return "Pharmacy"
    
    # Check for Mobile recharge-related keywords
    elif any(keyword in description for keyword in ["mobile", "phone", "recharge", "airtel", "jio", "vodafone", "idea", "bharti"]):
        return "Mobile recharge"
    
    # Check for Transfer-related keywords
    elif "transfer" in description:
        return "Transfer"
    
    # Check for UPI-related keywords
    elif "upi" in description:
        return "UPI Payment"
    
    # Default category if no match is found
    else:
        return "Uncategorized"


@app.route('/upload_pdf', methods=['POST'])
@is_logged_in
def upload_pdf():
    user_id = session.get('userID')
    if not user_id:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    if 'pdf_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['pdf_file']

    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)

    try:
        # Save the file to the specified directory
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Process the PDF file for withdrawal transactions
        withdrawals = extract_withdrawal_transactions(file_path)
        if withdrawals:
            save_withdrawals_to_db(withdrawals, user_id)

        flash('File uploaded and transactions processed successfully!', 'success')
        return redirect(url_for('addTransactions'))  # Redirect to a relevant route, like a dashboard

    except Exception as e:
        print(f"Error processing the PDF file: {e}")
        flash('Error processing the file', 'danger')
        return redirect(request.url)


def extract_withdrawal_transactions(file_path):
    transactions = []

    try:
        # Use pdfplumber to extract tables from the PDF
        with pdfplumber.open(file_path) as pdf:
            for page in pdf.pages:
                table = page.extract_table()
                
                if table:
                    # Convert the extracted table into a DataFrame for easier manipulation
                    df = pd.DataFrame(table[1:], columns=table[0])
                    
                    # Debugging output to check the first few rows
                    print(df.head())
                    
                    for index, row in df.iterrows():
                        print(f"Processing row {index}: {row}")  # Debugging output

                        if len(row) > 4:  # Ensure there are enough columns in the row
                            transaction_type = str(row[1])  # Assuming transaction type is in the second column

                            # Check if this is a withdrawal transaction
                            if is_withdrawal_transaction(transaction_type):
                                try:
                                    # Extract date and amount from relevant columns
                                    date_str = str(row[0]).strip()  # Assuming date is in the first column
                                    amount_str = str(row[4]).replace(",", "").strip()  # Assuming amount is in the fifth column

                                    # Debugging output for extracted values
                                    print(f"Extracted date: '{date_str}', amount: '{amount_str}'")

                                    # Check if date or amount fields are empty
                                    if not date_str or not amount_str:
                                        print(f"Skipping due to empty date or amount: {row}")
                                        continue

                                    # Convert date and amount
                                    transaction_date = dt.strptime(date_str, "%d-%m-%Y").date()
                                    amount = float(amount_str)

                                    # Ignore zero or invalid amounts
                                    if amount <= 0:
                                        print(f"Skipping non-positive amount transaction: {row}")
                                        continue

                                    # Assuming description can be constructed from other columns
                                    description = " ".join(map(str, row[2:4]))  # Adjust based on your actual data structure

                                    # Add the withdrawal transaction to the list
                                    transactions.append({
                                        "date": transaction_date,
                                        "description": description,
                                        "amount": amount,
                                        "category": infer_category(description)  # This function can be expanded as needed
                                    })

                                except ValueError as ve:
                                    print(f"Skipping invalid line due to parsing error: {row} - {ve}")
                                    continue

            print(f"Total transactions extracted: {len(transactions)}")

    except Exception as e:
        print(f"Error reading PDF with pdfplumber: {e}")
        flash('File error !','danger')

    return transactions

def is_withdrawal_transaction(transaction_type):
    """
    Determine if the transaction type indicates a withdrawal.
    This function can be expanded with more rules as needed.
    """
    withdrawal_keywords = ["UPI/DR", "Withdrawal", "Debit", "Transfer"]
    return any(keyword in transaction_type for keyword in withdrawal_keywords)
def save_withdrawals_to_db(transactions, user_id):
    try:
        with mysql.connection.cursor() as cur:
            for transaction in transactions:
                # Directly insert the transaction without checking for duplicates
                cur.execute("""
                    INSERT INTO transactions (user_id, date, description, amount, category)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    user_id,
                    transaction["date"],
                    transaction["description"],
                    int(transaction["amount"]),  # Use float to avoid integer truncation
                    transaction["category"]
                ))
                print(f"Transaction added: {transaction}")

            mysql.connection.commit()
            print("Transactions processed successfully.")
    except Exception as e:
        print(f"Database error: {e}")

@app.route('/chatbot', methods=['POST'])
def chatbot():
    user_id = session.get('userID')  # Use get to avoid KeyError if userID is not in session
    if not user_id:
        return jsonify({"response": "User  not logged in. Please log in first."}), 401

    message = request.json.get("message", "").lower()
    logging.debug(f"Received message: {message}")
    response = ""
    l=["show monthly budget","show category budgets","last transaction","most spent category this month","budget alerts","most expensive transaction this month","most expensive transaction this year"]
    try:
        with mysql.connection.cursor() as cursor:
            # Check if the user wants to see their budget
            if "show monthly budget" in message :
                cursor.execute("SELECT monthly_budget, monthly_savings_goal FROM user_budget WHERE user_id = %s", (user_id,))
                budget = cursor.fetchone()

                if budget:
                    response = f"Your monthly budget is {budget['monthly_budget']:.2f} and your savings goal is {budget['monthly_savings_goal']:.2f}."
                else:
                    response = "I couldn't find your budget details. Please set them first."
                return jsonify({"response": response})
            if "show category budgets" in message:
                cursor.execute("SELECT category, budget_limit FROM category_budgets WHERE user_id = %s", (user_id,))
                category_budgets = cursor.fetchall()

                if category_budgets:
                    response = "Your category budgets are:\n"
                    for budget in category_budgets:
                        response += f"{budget['category']}: ₹{budget['budget_limit']:.2f}\n"
                else:
                    response = "You don't have any category budgets set up."
                return jsonify({"response": response})
            if "last transaction" in message:
                cursor.execute("SELECT amount, description, category, date FROM transactions WHERE user_id = %s ORDER BY date DESC LIMIT 1", (user_id,))
                last_transaction = cursor.fetchone()

                if last_transaction:
                    response = f"Your last transaction was  ₹{last_transaction['amount']:.2f} for '{last_transaction['description']}' in the category '{last_transaction['category']}' on {last_transaction['date']}. "
                else:
                    response = "You have no transactions recorded."
                return jsonify({"response": response})
            if "most spent category this month" in message:
                cursor.execute("""
                    SELECT category, SUM(amount) as total_spent 
                    FROM transactions 
                    WHERE user_id = %s AND MONTH(date) = MONTH(CURRENT_DATE()) AND YEAR(date) = YEAR(CURRENT_DATE())
                    GROUP BY category 
                    ORDER BY total_spent DESC 
                    LIMIT 1
                """, (user_id,))
                most_spent_category = cursor.fetchone()

                if most_spent_category:
                    response = f"Your most spent category this month is '{most_spent_category['category']}' with a total of ${most_spent_category['total_spent']:.2f}."
                else:
                    response = "You have no transactions this month."
                return jsonify({"response": response})

            # Show most expensive transaction of the month
            if "budget alerts" in message:
                # Call the budget alerts logic
                cursor.execute("SELECT category, budget_limit FROM category_budgets WHERE user_id = %s", (user_id,))
                budgets = cursor.fetchall()
                print(budgets)

                alerts = []
                for budget in budgets:
                    category = budget['category']
                    budget_limit = budget['budget_limit']

                    # Calculate total spending for the current month for the category
                    cursor.execute("""
                        SELECT SUM(amount) as total_spent 
                        FROM transactions 
                        WHERE user_id = %s AND category = %s 
                        AND MONTH(date) = MONTH(CURRENT_DATE()) 
                        AND YEAR(date) = YEAR(CURRENT_DATE())
                    """, (user_id, category))
                    
                    total_spent = cursor.fetchone()['total_spent'] or 0

                    # Check if spending is approaching the limit
                    approaching_limit_threshold = Decimal('0.8')

                    # Check if spending is approaching the limit
                    if total_spent >= budget_limit * approaching_limit_threshold and total_spent < budget_limit:
                         alerts.append(f"Alert: You are approaching your budget limit for '{category}'. Current spending: ₹{total_spent:,.2f} out of ₹{budget_limit:,.2f}.")

                    # Check if spending exceeds the limit
                    if total_spent >= budget_limit:
                        alerts.append(f"Alert: You have exceeded your budget limit for '{category}'. Current spending: ₹{total_spent:,.2f} out of ₹{budget_limit:,.2f}.")
                # Prepare the response
                if alerts:
                    response = "\n".join(alerts)
                else:
                    response = "You are within your budget limits for all categories."

                return jsonify({"response": response})
            if "most expensive transaction this month" in message:
                cursor.execute("""
                    SELECT amount, description, category, date 
                    FROM transactions 
                    WHERE user_id = %s AND MONTH(date) = MONTH(CURRENT_DATE()) AND YEAR(date) = YEAR(CURRENT_DATE())
                    ORDER BY amount DESC 
                    LIMIT 1
                """, (user_id,))
                most_expensive_transaction = cursor.fetchone()

                if most_expensive_transaction:
                    response = f"The most expensive transaction this month was  ₹{most_expensive_transaction['amount']:.2f} for '{most_expensive_transaction['description']}' in the category '{most_expensive_transaction['category']}' on {most_expensive_transaction['date']}."
                else:
                    response = "You have no transactions this month."
                return jsonify({"response": response})

            # Show most expensive transaction of the year
            if "most expensive transaction this year" in message:
                cursor.execute("""
                    SELECT amount, description, category, date 
                    FROM transactions 
                    WHERE user_id = %s AND YEAR(date) = YEAR(CURRENT_DATE())
                    ORDER BY amount DESC 
                    LIMIT 1
                """, (user_id,))
                most_expensive_transaction_year = cursor.fetchone()

                if most_expensive_transaction_year:
                    response = f"The most expensive transaction this year was  ₹{most_expensive_transaction_year['amount']:.2f} for '{most_expensive_transaction_year['description']}' in the category '{most_expensive_transaction_year['category']}' on {most_expensive_transaction_year['date']}."
                else:
                    response = "You have no transactions this year."
                return jsonify({"response": response})
            # If the user asks something else
            n=random.randint(0,len(l))
            response = "I'm sorry, I didn't understand that. try commands like ",l[n] 

    except Exception as e:
        logging.error(f"Error: {e}")
        response = "An error occurred while processing your request. Please try again later."

    return jsonify({"response": response})

@app.route('/budget_alerts', methods=['POST'])
def budget_alerts():
    user_id = session.get('userID')
    if not user_id:
        return jsonify({"response": "User  not logged in. Please log in first."}), 401

    try:
        # Connect to the MySQL database
        with mysql.connector.cursor as cursor :

        # Fetch user's budget limits
            cursor.execute("SELECT category, budget_limit FROM category_budgets WHERE user_id = %s", (user_id,))
            budgets = cursor.fetchall()

            alerts = []
            for budget in budgets:
                category = budget['category']
                budget_limit = budget['budget_limit']

                # Calculate total spending for the current month for the category
                cursor.execute("""
                    SELECT SUM(amount) as total_spent 
                    FROM transactions 
                    WHERE user_id = %s AND category = %s 
                    AND MONTH(date) = MONTH(CURRENT_DATE()) 
                    AND YEAR(date) = YEAR(CURRENT_DATE())
                """, (user_id, category))
                
                total_spent = cursor.fetchone()['total_spent'] or 0

                # Check if spending is approaching the limit
                if total_spent >= budget_limit * 0.8 and total_spent < budget_limit:
                    alerts.append(f"Alert: You are approaching your budget limit for '{category}'. Current spending: ₹{total_spent:,.2f} out of ₹{budget_limit:,.2f}.")

                # Check if spending exceeds the limit
                if total_spent >= budget_limit:
                    alerts.append(f"Alert: You have exceeded your budget limit for '{category}'. Current spending: ₹{total_spent:,.2f} out of ₹{budget_limit:,.2f}.")

        # Prepare the response
        if alerts:
            response = "\n".join(alerts)
        else:
            response = "You are within your budget limits for all categories."

    except Exception as e:
        logging.error(f"Error: {e}")
        response = "An error occurred while processing your budget alerts. Please try again later."
    finally:
        # Close the database connection
        if cursor:
            cursor.close()
        

    return jsonify({"response": response})

@app.route('/addTransactions', methods=['GET', 'POST'])
@is_logged_in
def addTransactions():
    if request.method == 'POST':
        # Handle regular form submission
        if 'amount' in request.form:
            amount = request.form['amount']
            description = request.form['description']
            category = request.form['category']

            # Insert the transaction into the database
            with mysql.connection.cursor() as cur:
                cur.execute("INSERT INTO transactions(user_id, amount, description, category) VALUES(%s, %s, %s, %s)",
                            (session['userID'], amount, description, category))
                mysql.connection.commit()

                # Flash a success message after the transaction is recorded
                flash('Transaction Successfully Recorded', 'success')

                # Redirect to avoid resubmission
                return redirect(url_for('addTransactions'))

    # Fetch total expenses and transactions for rendering
    with mysql.connection.cursor() as cur:
        cur.execute("SELECT SUM(amount) FROM transactions WHERE MONTH(date) = MONTH(CURRENT_DATE()) AND YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = %s", [session['userID']])
        totalExpenses = cur.fetchone()['SUM(amount)'] or 0

        cur.execute("SELECT * FROM transactions WHERE MONTH(date) = MONTH(CURRENT_DATE()) AND YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = %s ORDER BY date DESC", [session['userID']])
        transactions = cur.fetchall()

        for transaction in transactions:
            transaction['date'] = timeago.format(transaction['date'], datetime.now()) if datetime.now() - transaction['date'] < timedelta(days=0.5) else transaction['date'].strftime('%d %B, %Y')

        return render_template('addTransactions.html', totalExpenses=totalExpenses, transactions=transactions)
@app.route('/transactionHistory',methods=['GET','POST'])
@is_logged_in
def transactionHistory():
    user_id = session['userID']
    selected_category = request.args.get('category', default=None)

    with mysql.connection.cursor() as cur:
        cur.execute("SELECT DISTINCT category FROM transactions WHERE user_id = %s", [user_id])
        categories = cur.fetchall()

        if request.method == 'POST':
            month = request.form['month']
            year = request.form['year']
            if month == "00":
                cur.execute("SELECT SUM(amount) FROM transactions WHERE YEAR(date) = %s AND user_id = %s", [year, user_id])
            else:
                cur.execute("SELECT SUM(amount) FROM transactions WHERE MONTH(date) = %s AND YEAR(date) = %s AND user_id = %s", [month, year, user_id])
            totalExpenses = cur.fetchone()['SUM(amount)'] or 0

            cur.execute("SELECT * FROM transactions WHERE MONTH(date) = %s AND YEAR(date) = %s AND user_id = %s ORDER BY date DESC", [month, year, user_id])
            transactions = cur.fetchall()
        else:
            cur.execute("SELECT SUM(amount) FROM transactions WHERE user_id = %s", [user_id])
            totalExpenses = cur.fetchone()['SUM(amount)'] or 0
            category_filter = f"AND category = '{selected_category}'" if selected_category else ''
            cur.execute(f"SELECT * FROM transactions WHERE user_id = %s {category_filter} ORDER BY date DESC", [user_id])
            transactions = cur.fetchall()

        for transaction in transactions:
            transaction['date'] = transaction['date'].strftime('%d %B, %Y')

        return render_template('transactionHistory.html', totalExpenses=totalExpenses, transactions= transactions, categories=categories, selected_category=selected_category)

@app.route('/track_budget', methods=['GET', 'POST'])
@is_logged_in
def track_budget():
    user_id = session.get('userID')
    if not user_id:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    with mysql.connection.cursor() as cur:
        cur.execute("SELECT password FROM users WHERE id = %s", [user_id])
        user = cur.fetchone()

        if request.method == 'POST':
            password_input = request.form.get('password')
            monthly_budget = request.form.get('monthly_budget')
            monthly_savings_goal = request.form.get('monthly_savings_goal')

            if sha256_crypt.verify(password_input, user['password']):
                # Check if the user has reached the monthly update limit
                cur.execute("""
                    SELECT COUNT(*) as update_count 
                    FROM user_budget 
                    WHERE user_id = %s AND MONTH(updated_at) = MONTH(CURRENT_DATE()) AND YEAR(updated_at) = YEAR(CURRENT_DATE())
                """, [user_id])
                update_count = cur.fetchone()['update_count']

                if True:
                    # Check if the user's budget already exists
                    cur.execute("SELECT * FROM user_budget WHERE user_id = %s", [user_id])
                    exists = cur.fetchone()

                    if exists:
                        # Update the existing budget
                        cur.execute("""
                            UPDATE user_budget 
                            SET monthly_budget = %s, monthly_savings_goal = %s, updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = %s
                        """, (monthly_budget, monthly_savings_goal, user_id))
                    else:
                        # Insert a new budget
                        cur.execute("""
                            INSERT INTO user_budget (user_id, monthly_budget, monthly_savings_goal)
                            VALUES (%s, %s, %s)
                        """, (user_id, monthly_budget, monthly_savings_goal))

                    mysql.connection.commit()
                    flash('Budget updated successfully', 'success')
                else:
                    flash('You have reached the maximum number of updates for this month.', 'warning')
            else:
                flash('Invalid password. Please try again.', 'danger')

        # Fetch the user's current budget data
        cur.execute("SELECT monthly_budget, monthly_savings_goal FROM user_budget WHERE user_id = %s", [user_id])
        budget_data = cur.fetchone()

        if not budget_data:
            budget_data = {'monthly_budget': 0, 'monthly_savings_goal': 0}

        monthly_budget = budget_data['monthly_budget']
        monthly_savings_goal = budget_data['monthly_savings_goal']

        # Fetch total spending for the month
        cur.execute("""
            SELECT COALESCE(SUM(amount), 0) as total_spent
            FROM transactions
            WHERE user_id = %s AND MONTH(date) = MONTH(CURRENT_DATE()) AND YEAR(date) = YEAR(CURRENT_DATE())
        """, [user_id])
        total_spent = cur.fetchone()['total_spent']

        # Calculate remaining budget
        remaining_budget = monthly_budget - monthly_savings_goal - total_spent

        # Calculate progress
        if remaining_budget > 0:
            progress_percentage = (total_spent / remaining_budget) * 100
        else:
            progress_percentage = 100 if total_spent > 0 else 0

        # Fetch category budgets and calculate goals met and missed
        # Execute the SQL query to get the current spending for each category
        cur.execute("""
    SELECT cb.category, cb.budget_limit,
           COALESCE(SUM(t.amount), 0) as current_spending
    FROM category_budgets cb
    LEFT JOIN transactions t ON cb.category = t.category 
        AND cb.user_id = t.user_id 
        AND MONTH(t.date) = MONTH(CURRENT_DATE())
        AND YEAR(t.date) = YEAR(CURRENT_DATE())
    WHERE cb.user_id = %s
    GROUP BY cb.category, cb.budget_limit
""", [user_id])

# Fetch the results
        category_budgets = cur.fetchall()
        

        # Initialize counters for goals met and missed
        goals_met = 0
        goals_missed = 0

        # Iterate through the category budgets to check spending against budget limits
        for budget in category_budgets:
            if budget['current_spending'] <= budget['budget_limit']:
                goals_met += 1
            else:
                goals_missed += 1  # Count goals missed

        # Prepare data for visualization
        goals_data = {
            'goals_met': goals_met,
            'goals_missed': goals_missed
        }
        monthly_goals_met = 0
        monthly_goals_missed = 0

        if total_spent <= remaining_budget:
            monthly_goals_met += 1
        else:
            monthly_goals_missed += 1

       
        
       

# Assuming you have other variables like progress_percentage, remaining_budget, total_spent, and budget_data defined
    return render_template(
    'track_budget.html',
    progress_percentage=progress_percentage,
    float=float,
    remaining_budget=remaining_budget,
    total_spent=total_spent,
    budget_data=budget_data,
    
    
    category_budgets=category_budgets,
    goals_data=goals_data
)

      
@app.route('/set_category_budget', methods=['POST'])
@is_logged_in
def set_category_budget():
    user_id = session['userID']
    category = request.form.get('category')
    budget_limit = request.form.get('budget_limit')

    with mysql.connection.cursor() as cur:
        cur.execute("SELECT * FROM category_budgets WHERE user_id = %s AND category = %s", (user_id, category))
        existing_budget = cur.fetchone()

        if existing_budget:
            flash('Budget limit already exists. Delete this current one to proceed.', 'danger')
        else:
            try:
                # Insert the new budget limit if it doesn't exist
                cur.execute("INSERT INTO category_budgets (user_id, category, budget_limit) VALUES (%s, %s, %s)", (user_id, category, budget_limit))
                mysql.connection.commit()
                flash('Category budget set successfully', 'success')
            except IntegrityError:
                mysql.connection.rollback()  # Rollback the transaction in case of an error
                flash('An error occurred while setting the budget. Please try again.', 'danger')

    return redirect(url_for('track_budget'))
@app.route('/category_budget/delete/<category>', methods=['POST'])
@is_logged_in
def delete_category_budget(category):
    user_id=session['userID']
    if not user_id:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    with mysql.connection.cursor() as cur:
        try:
            cur.execute("DELETE FROM category_budgets WHERE user_id = %s AND category = %s", (user_id, category))
            mysql.connection.commit()
            flash('Category budget deleted successfully', 'success')
        except Exception as e:
            flash('Error deleting category budget', 'danger')
            print(f"Error: {e}")

    return redirect(url_for('track_budget'))

@app.route('/deleteTransaction/<string:id>', methods=['POST'])
@is_logged_in
def deleteTransaction(id):
    with mysql.connection.cursor() as cur:
        cur.execute("DELETE FROM transactions WHERE id = %s", [id])
        mysql.connection.commit()

    flash('Transaction Deleted', 'success')
    return redirect(url_for('transactionHistory'))



@app.route('/editCurrentMonthTransaction/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def deleteCurrentMonthTransaction(id):
    with mysql.connection.cursor() as cur:
        cur.execute("DELETE FROM transactions WHERE id = %s", [id])
        mysql.connection.commit()

    flash('Transaction Deleted', 'success')
    return redirect(url_for('addTransactions'))



@app.route('/category')
def createBarCharts():
    with mysql.connection.cursor() as cur:
        cur.execute("SELECT SUM(amount) AS amount, category FROM transactions WHERE YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = %s GROUP BY category ORDER BY category", [session['userID']])
        transactions = cur.fetchall()

        values = [transaction['amount'] for transaction in transactions]
        labels = [transaction['category'] for transaction in transactions]

        fig = go.Figure(data=[go.Pie(labels=labels, values=values)])
        fig.update_traces(textinfo='label+value', hoverinfo='percent')
        fig.update_layout(title_text='Category Wise Pie Chart For Current Year')
        fig.show()

    return redirect(url_for('addTransactions'))

@app.route('/yearly_bar')
def yearlyBar():
    with mysql.connection.cursor() as cur:
        year_data = []
        for month in range(1, 13):
            cur.execute("SELECT SUM(amount) FROM transactions WHERE MONTH(date ) = %s AND YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = %s", (month, session['userID']))
            year_data.append(cur.fetchone()['SUM(amount)'] or 0)

        last_year_data = []
        for month in range(1, 13):
            cur.execute("SELECT SUM(amount) FROM transactions WHERE MONTH(date) = %s AND YEAR(date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 YEAR)) AND user_id = %s", (month, session['userID']))
            last_year_data.append(cur.fetchone()['SUM(amount)'] or 0)

        year_labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        fig = go.Figure(data=[
            go.Bar(name='Last Year', x=year_labels, y=last_year_data),
            go.Bar(name='This Year', x=year_labels, y=year_data)
        ])
        fig.update_layout(barmode='group', title_text='Comparison Between This Year and Last Year')
        fig.show()

    return redirect(url_for('addTransactions'))

@app.route('/monthly_bar')
def monthlyBar():
    with mysql.connection.cursor() as cur:
        cur.execute("SELECT SUM(amount) as amount, MONTH(date) as month FROM transactions WHERE YEAR(date) = YEAR(CURRENT_DATE()) AND user_id = %s GROUP BY MONTH(date) ORDER BY MONTH(date)", [session['userID']])
        transactions = cur.fetchall()

        months = []
        values = []

        for transaction in transactions:
            if 'month' in transaction and 'amount' in transaction:
                months.append(transaction['month'])
                values.append(transaction['amount'])

        fig = go.Figure([go.Bar(x=months, y=values)])
        fig.update_layout(title_text='Monthly Bar Chart For Current Year')
        fig.show()

    return redirect(url_for('addTransactions'))
@app.route('/dashboard', methods=['GET'])
@is_logged_in
def dashboard():
    user_id = session['userID']
    
    if not user_id:
        flash('User  ID not found in session. Please log in again.', 'danger')
        return redirect(url_for('login'))

    with mysql.connection.cursor() as cur:
        # Get spending data for the last month
        thirty_days_ago = datetime.now() - timedelta(days=30)
        cur.execute('''
            SELECT DATE(date) as date, SUM(amount) as amount
            FROM transactions
            WHERE user_id = %s AND date >= %s
            GROUP BY DATE(date)
            ORDER BY date
        ''', (user_id, thirty_days_ago))

        rows = cur.fetchall()
        print("Rows fetched:", rows)

        # Prepare data for the daily spending chart
        daily_spending = []
        for row in rows:
            daily_spending.append({
                'date': row['date'].strftime('%Y-%m-%d'),  # Format date as string
                'amount': float(row['amount']) if row['amount'] is not None else 0.0
            })

        print("Daily Spending Data:", daily_spending)

        # Get category-wise spending
        cur.execute('''
            SELECT category, SUM(amount) as amount
            FROM transactions
            WHERE user_id = %s
            GROUP BY category
        ''', (user_id,))
        
        category_spending = [{'category': row['category'], 'amount': float(row['amount'])} for row in cur.fetchall()]

        # Get total spending
        cur.execute('''
            SELECT 
                SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as total_spending
            FROM transactions
            WHERE user_id = %s
        ''', (user_id,))
        
        financial_summary = cur.fetchone()
        financial_summary = {
            'total_spending': float(financial_summary['total_spending']) if financial_summary['total_spending'] is not None else 0
        }

    return render_template('dashboard.html', user_id=user_id, 
                           daily_spending=daily_spending,
                           category_spending=category_spending, 
                           financial_summary=financial_summary)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
