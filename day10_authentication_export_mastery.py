# Day 6 FIXED: Web Application Foundations
from flask import Flask, request, session, send_file
import sqlite3
import re
import hashlib
import csv
import io


def get_database_connection():
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS customers
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT, location TEXT, amount INTEGER)''')
    conn.commit()
    return conn


def initialize_products_table():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS products
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT, revenue INTEGER, units INTEGER)''')
    conn.commit()
    conn.close()


def populate_products_table():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        products = [
            ('Laptop', 14985, 45),
            ('Monitor', 13500, 90),
            ('Keyboard', 8750, 125),
            ('Mouse', 6200, 155)
        ]
        cursor.executemany("INSERT INTO products (name, revenue, units) VALUES (?, ?, ?)", products)
        conn.commit()
    conn.close()


def initialize_users_table():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password_hash TEXT)''')
    conn.commit()
    conn.close()

def hash_password(password):
    password_bytes = password.encode('utf-8')
    hash_object = hashlib.sha256(password_bytes)
    password_hash = hash_object.hexdigest()
    return password_hash

def test_password_hashing():
    test_password = "password123"
    hash1 = hash_password(test_password)
    hash2 = hash_password(test_password)
    print(f"\n=== PASSWORD HASHING TEST ===")
    print(f"Original password: {test_password}")
    print(f"Hash result: {hash1}")
    print(f"Same input gives same hash: {hash1 == hash2}")

def test_users_table():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash FROM users")
    users = cursor.fetchall()
    conn.close()
    print(f"\n=== USERS TABLE TEST ===")
    print(f"Total users: {len(users)}")
    for user in users:
        print(f"Username: {user[0]}, Password Hash: {user[1][:20]}...")







def initialize_database():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM customers")
    if cursor.fetchone()[0] == 0:
        for customer in all_customers:
            cursor.execute("INSERT INTO customers (name, location, amount) VALUES (?, ?, ?)",
                           (customer['name'], customer['location'], customer['amount']))
        conn.commit()
    conn.close()

def test_database_contents():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM customers")
    rows = cursor.fetchall()
    print(f"Database contains {len(rows)} customers:")
    for row in rows:
        print(f"  ID: {row[0]}, Name: {row[1]}, Location: {row[2]}, Amount: {row[3]}")
    conn.close()

def find_duplicate_customers():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM customers")
    names = [row[0] for row in cursor.fetchall()]
    seen = {}
    duplicates = []
    for name in names:
        if name in seen:
            duplicates.append(name)
        seen[name] = True
    conn.close()
    return duplicates

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True
    return False

def test_email_validation():
    test_cases = [
        ("john@email.com", True),
        ("notanemail", False),
        ("missing@domain", False)
    ]
    for email, expected in test_cases:
        result = validate_email(email)
        status = "✅" if result == expected else "❌"
        print(f"{status} {email}: {result} (expected {expected})")


def test_duplicate_detection():
    duplicates = find_duplicate_customers()
    if duplicates:
        print(f"⚠️ Found {len(duplicates)} duplicate customer names: {duplicates}")
    else:
        print("✅ No duplicate customer names found.")


def calculate_loyalty_points(customer_name):
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT location, amount FROM customers WHERE name = ?", (customer_name,))
    result = cursor.fetchone()
    conn.close()

    location, amount = result
    points = amount
    if amount >= 800:
        points = amount * 2
    elif amount >= 500:
        points = amount * 1.5

    if location == "Houston":
        points += 100

    return int(points)

def rank_customers_by_composite_score():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name, amount FROM customers")
    customers = cursor.fetchall()
    conn.close()

    ranked = []
    for name, amount in customers:
        loyalty_points = calculate_loyalty_points(name)
        composite_score = (amount * 0.6) + (loyalty_points * 0.4)
        ranked.append({'name': name, 'amount': amount, 'loyalty': loyalty_points, 'score': composite_score})
    ranked.sort(key=lambda x: x['score'], reverse=True)
    return ranked

def test_customer_ranking():
    print("\n=== CUSTOMER RANKING TEST ===")
    ranked = rank_customers_by_composite_score()
    for i, customer in enumerate(ranked, 1):
        print(f"#{i}: {customer['name']} - Amount: ${customer['amount']}, Loyalty: {customer['loyalty']}, Score: {customer['score']:.1f}")



def test_loyalty_points():
    print("\n=== LOYALTY POINTS TEST ===")
    test_customers = ["Sarah", "Chris", "Sade", "Lisa"]
    for name in test_customers:
        points = calculate_loyalty_points(name)
        print(f"{name}: {points} loyalty points")

# Global customer data that persists
all_customers = [
    {'name': 'Lisa', 'location': 'Houston', 'amount': 890},
    {'name': 'Chris', 'location': 'Seattle', 'amount': 680},
    {'name': 'Mike', 'location': 'Denver', 'amount': 450},
    {'name': 'Sarah', 'location': 'Portland', 'amount': 320},
    {'name': 'Sade', 'location': 'New Jersey', 'amount': 789}
]

# Create web application
app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'

# Initialize database on startup
get_database_connection()
initialize_database()
test_database_contents()
test_duplicate_detection()
test_email_validation()
initialize_products_table()
populate_products_table()
initialize_users_table()
test_password_hashing()
test_users_table()
test_loyalty_points()
test_customer_ranking()



# ADD THE LINEAR SEARCH ALGORITHM
def search_customer_by_name(search_name):
    found_customers = []
    for customer in all_customers:
        if customer['name'].lower() == search_name.lower():
            found_customers.append(customer)
    return found_customers

# Implement Bubble Sort
def sort_customers_by_amount():
    sorted_customers = all_customers.copy()
    n = len(sorted_customers)

    for i in range(n):
        for j in range(0, n - i - 1):
            if sorted_customers[j]['amount'] < sorted_customers[j + 1]['amount']:
                # Swap customers (higher amounts first)
                sorted_customers[j], sorted_customers[j + 1] = sorted_customers[j + 1], sorted_customers[j]

def calculate_customer_statistics():
    amounts = [customer['amount'] for customer in all_customers]
    
    # Calculate mean (average)
    total = sum(amounts)
    mean = total // len(amounts)
    
    # Calculate median (middle value)
    sorted_amounts = sorted(amounts, reverse=True)
    n = len(sorted_amounts)
    median = sorted_amounts[n // 2] if n % 2 == 1 else (sorted_amounts[n//2-1] + sorted_amounts[n//2]) // 2
    
    return {'mean': mean, 'median': median, 'total': total, 'count': len(amounts)}

    return sorted_customers

def validate_customer_data(name, location, amount):
    errors = []
    
    # Check if name is empty or too short
    if not name or len(name.strip()) < 2:
        errors.append("Name must be at least 2 characters")
    
    # Check if location contains only letters and spaces
    if not location or not all(c.isalpha() or c.isspace() for c in location):
        errors.append("Location must contain only letters and spaces")
    
    # Check if amount is positive
    if amount < 0:
        errors.append("Amount must be positive")
    
    return errors

# Create main dashboard page
@app.route('/', methods=['GET', 'POST'])
def home():
    # Check if user is logged in
    logged_in_user = session.get('username')
    # Get threshold from form, default to 500
    threshold = 500
    if request.method == 'POST':
        threshold = int(request.form.get('threshold', 500))

    
    
    # Filter VIP customers by threshold
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM customers WHERE amount >= ?", (threshold,))
    filtered_customers = [{'id': row[0], 'name': row[1], 'location': row[2], 'amount': row[3]}
                          for row in cursor.fetchall()]
    

    # Create dashboard HTML
    html = "<h1>VIP Customer Alert Dashboard</h1>"
    if logged_in_user:
        html += f"<p>Logged in as: {logged_in_user}</p>"
    html += '<style>'
    html += 'body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }'
    html += 'h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }'
    html += 'nav { background: linear-gradient(45deg, #3498db, #2980b9); padding: 15px; border-radius: 5px; }'
    html += 'nav a { color: white; text-decoration: none; margin-right: 20px; font-weight: bold; }'
    html += '</style>'
    html += '<nav style="background-color: #f0f0f0; padding: 10px; margin-bottom: 20px;">'
    html += '<a href="/" style="margin-right: 15px; color: blue;">Dashboard</a>'
    html += '<a href="/customers" style="margin-right: 15px; color: blue;">All Customers</a>'
    html += '<a href="/products" style="margin-right: 15px; color: blue;">Products</a>'
    html += '<a href="/search" style="margin-right: 15px; color: blue;">Search</a>'
    html += '<a href="/sorted_customers" style="margin-right: 15px; color: blue;">Sorted Customers</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/export_csv" style="margin-right: 15px; color: blue;">Export CSV</a>'
    html += '<a href="/logout" style="margin-right: 15px; color: blue;">Logout</a>'
    html += '</nav>'
    html += "<h2>High-Value Customers Detected:</h2>"

    for customer in filtered_customers:
        html += f"<p>VIP: {customer['name']} ({customer['location']}) - ${customer['amount']}</p>"

    # Advanced Business Analytics
    cursor.execute("SELECT COUNT(*), SUM(amount) FROM customers")
    total_customers, total_revenue = cursor.fetchone()
    average_purchase = total_revenue // total_customers if total_customers > 0 else 0
    vip_count = len(filtered_customers)

    conn.close()

    html += "<h2>Business Intelligence Summary:</h2>"
    html += f"<p><strong>Total Customers:</strong> {total_customers}</p>"
    html += f"<p><strong>Total Revenue:</strong> ${total_revenue}</p>"
    html += f"<p><strong>Average Purchase:</strong> ${average_purchase}</p>"
    html += f"<p><strong>VIP Customers (Above Threshold):</strong> {vip_count}</p>"

    # Top products from Day 5
    top_products = [
        {'name': 'Laptop', 'revenue': 14985},
        {'name': 'Monitor', 'revenue': 13500}
    ]

    html += "<h2>Top Revenue Products:</h2>"
    for product in top_products:
        html += f"<p>Top Product: {product['name']} - ${product['revenue']}</p>"

    html += "<h2>Adjust VIP Threshold:</h2>"
    html += '<form method="POST">'
    html += f'<input type="number" name="threshold" placeholder="Enter new threshold" value="{threshold}">'
    html += '<button type="submit">Update VIP Threshold</button>'
    html += '</form>'
    
    return html

@app.route('/customers')
def customers_page():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM customers")
    customers = [{'id': row[0], 'name': row[1], 'location': row[2], 'amount': row[3]}
                  for row in cursor.fetchall()]
    conn.close()
    

    html = "<h1>All Customers Report</h1>"
    html += '<style>'
    html += 'body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }'
    html += 'h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }'
    html += 'nav { background: linear-gradient(45deg, #3498db, #2980b9); padding: 15px; border-radius: 5px; }'
    html += 'nav a { color: white; text-decoration: none; margin-right: 20px; font-weight: bold; }'
    html += '</style>'
    html += '<nav style="background-color: #f0f0f0; padding: 10px; margin-bottom: 20px;">'
    html += '<a href="/" style="margin-right: 15px; color: blue;">Dashboard</a>'
    html += '<a href="/customers" style="margin-right: 15px; color: blue;">All Customers</a>'
    html += '<a href="/products" style="margin-right: 15px; color: blue;">Products</a>'
    html += '<a href="/search" style="margin-right: 15px; color: blue;">Search</a>'
    html += '<a href="/sorted_customers" style="margin-right: 15px; color: blue;">Sorted Customers</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/export_csv" style="margin-right: 15px; color: blue;">Export CSV</a>'
    html += '</nav>'
    
    for customer in all_customers:
        html += f"<p>Customer: {customer['name']} ({customer['location']}) - ${customer['amount']}</p>"
    
    html += '<p><a href="/">Back to Dashboard</a></p>'
    # Add new customer form
    html += "<h2>Add New Customer:</h2>"
    html += '<form method="POST" action="/add_customer">'
    html += '<input type="text" name="customer_name" placeholder="Customer Name" required>'
    html += '<input type="text" name="customer_location" placeholder="Location" required>'
    html += '<input type="number" name="customer_amount" placeholder="Purchase Amount" required>'
    html += '<button type="submit">Add Customer</button>'
    html += '</form>'

    return html

@app.route('/products')
def products_page():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products")
    all_products = [{'name': row[1], 'revenue': row[2], 'units': row[3]}
                    for row in cursor.fetchall()]
    conn.close()




    html = "<h1>Product Performance Analytics</h1>"
    html += '<style>'
    html += 'body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }'
    html += 'h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }'
    html += 'nav { background: linear-gradient(45deg, #3498db, #2980b9); padding: 15px; border-radius: 5px; }'
    html += 'nav a { color: white; text-decoration: none; margin-right: 20px; font-weight: bold; }'
    html += '</style>'
    html += '<nav style="background-color: #f0f0f0; padding: 10px; margin-bottom: 20px;">'
    html += '<a href="/" style="margin-right: 15px; color: blue;">Dashboard</a>'
    html += '<a href="/customers" style="margin-right: 15px; color: blue;">All Customers</a>'
    html += '<a href="/products" style="margin-right: 15px; color: blue;">Products</a>'
    html += '<a href="/search" style="margin-right: 15px; color: blue;">Search</a>'
    html += '<a href="/sorted_customers" style="margin-right: 15px; color: blue;">Sorted Customers</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/export_csv" style="margin-right: 15px; color: blue;">Export CSV</a>'
    html += '</nav>'

    for product in all_products:
        html += f"<p>Product: {product['name']} - Revenue: ${product['revenue']} - Units Sold: {product['units']}</p>"
    
    return html

@app.route('/add_customer', methods=['POST'])
def add_customer():
    # Get form data
    name = request.form.get('customer_name', '').strip()
    location = request.form.get('customer_location', '').strip()
    
    try:
        amount = int(request.form.get('customer_amount', 0))
    except ValueError:
        amount = -1  # Force validation error for non-numeric input
    
    # Validate the data
    errors = validate_customer_data(name, location, amount)
    
    if errors:
        # Show errors if validation fails
        html = "<h1>Error Adding Customer</h1>"
        for error in errors:
            html += f"<p style='color: red;'>Error: {error}</p>"
        html += '<p><a href="/customers">Try Again</a></p>'
    else:
        # Add customer if validation passes
        conn = get_database_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO customers (name, location, amount) VALUES (?, ?, ?)",
                       (name, location, amount))
        conn.commit()
        conn.close()

        html = "<h1>Customer Added Successfully!</h1>"
        html += f"<p>New Customer: {name} from {location} - ${amount}</p>"
        html += '<p><a href="/customers">Back to Customers</a></p>'
    
    return html

@app.route('/search')
def search_page():
    html = "<h1>Customer Search</h1>"
    html += '<nav style="background-color: #f0f0f0; padding: 10px; margin-bottom: 20px;">'
    html += '<a href="/" style="margin-right: 15px; color: blue;">Dashboard</a>'
    html += '<a href="/customers" style="margin-right: 15px; color: blue;">All Customers</a>'
    html += '<a href="/products" style="margin-right: 15px; color: blue;">Products</a>'
    html += '<a href="/search" style="margin-right: 15px; color: blue;">Search</a>'
    html += '<a href="/sorted_customers" style="margin-right: 15px; color: blue;">Sorted Customers</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/export_csv" style="margin-right: 15px; color: blue;">Export CSV</a>'
    html += '</nav>'
    
    html += '<form method="POST" action="/search_results">'
    html += '<input type="text" name="search_name" placeholder="Enter customer name" required>'
    html += '<button type="submit">Search Customer</button>'
    html += '</form>'
    
    return html

@app.route('/search_results', methods=['POST'])
def search_results():
    search_name = request.form.get('search_name')
    found_customers = search_customer_by_name(search_name)
    
    html = f"<h1>Search Results for '{search_name}'</h1>"
    
    if found_customers:
        for customer in found_customers:
            html += f"<p>Found: {customer['name']} ({customer['location']}) - ${customer['amount']}</p>"
    else:
        html += "<p>No customers found with that name.</p>"
    
    html += '<p><a href="/search">Search Again</a></p>'
    return html


@app.route('/sorted_customers')
def sorted_customers():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM customers ORDER BY amount DESC")
    sorted_list = [{'name': row[1], 'location': row[2], 'amount': row[3]}
                   for row in cursor.fetchall()]
    conn.close()
    
    html = "<h1>Customers Sorted by Spending (Highest First)</h1>"
    html += '<nav style="background-color: #f0f0f0; padding: 10px; margin-bottom: 20px;">'
    html += '<a href="/" style="margin-right: 15px; color: blue;">Dashboard</a>'
    html += '<a href="/customers" style="margin-right: 15px; color: blue;">All Customers</a>'
    html += '<a href="/search" style="margin-right: 15px; color: blue;">Search</a>'
    html += '<a href="/sorted_customers" style="margin-right: 15px; color: blue;">Sorted View</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/export_csv" style="margin-right: 15px; color: blue;">Export CSV</a>'
    html += '</nav>'
    
    for customer in sorted_list:
        html += f"<p>#{sorted_list.index(customer)+1}: {customer['name']} - ${customer['amount']} ({customer['location']})</p>"
    
    return html


@app.route('/analytics')
def analytics_page():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*), SUM(amount), AVG(amount) FROM customers")
    count, total, average = cursor.fetchone()
    
    

    # Get median (middle value) Before closing connection
    middle_position = (count // 2) + 1 if count % 2 == 1 else count // 2
    cursor.execute("SELECT amount FROM customers ORDER BY amount LIMIT 1 OFFSET ?",
                   (middle_position - 1,))
    median = cursor.fetchone()[0]

    conn.close() # Close after all database work is done

    stats = {'count': count, 'total': total, 'mean': average, 'median': median}
    
    html = "<h1>Business Analytics Dashboard</h1>"
    html += '<nav style="background-color: #f0f0f0; padding: 10px; margin-bottom: 20px;">'
    html += '<a href="/" style="margin-right: 15px; color: blue;">Dashboard</a>'
    html += '<a href="/customers" style="margin-right: 15px; color: blue;">All Customers</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/sorted_customers" style="margin-right: 15px; color: blue;">Sorted Customers</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/export_csv" style="margin-right: 15px; color: blue;">Export CSV</a>'
    html += '</nav>'
    
    html += f"<p><strong>Total Customers:</strong> {stats['count']}</p>"
    html += f"<p><strong>Total Revenue:</strong> ${stats['total']}</p>"
    html += f"<p><strong>Average Purchase:</strong> ${stats['mean']}</p>"
    html += f"<p><strong>Median Purchase:</strong> ${stats['median']}</p>"
    
    return html

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        html = "<h1>User Registration</h1>"
        html += '<form method="POST">'
        html += '<input type="text" name="username" placeholder="Username" required>'
        html += '<input type="password" name="password" placeholder="Password" required>'
        html += '<button type="submit">Register</button>'
        html += '</form>'
        return html
    else: # Post request
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_database_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

    if existing_user:
        html = "<h1>Registration Failed</h1>"
        html += "<p>Username already exists. Please choose another.</p>"
        html += '<p><a href="/register">Try Again</a></p>'
        return html
    else:
        password_hash = hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, password_hash))
        conn.commit()
        conn.close()

        html = "<h1>Registration Successful!</h1>"
        html += f"<p>Welcome, {username}! Your account has been created.</p>"
        html += '<p><a href="/login">Login Now</a></p>'
        return html

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        html = "<h1>Login</h1>"
        html += '<form method="POST">'
        html += '<input type="text" name="username" placeholder="Username" required><br><br>'
        html += '<input type="password" name="password" placeholder="Password" required><br><br>'
        html += '<button type="submit">Login</button>'
        html += '</form>'
        html += '<p><a href="/register">Need an account? Register here.</a></p>'
        return html
    else: # Post request
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_database_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
    if not user:
        html = "<h1>Login Failed</h1>"
        html += "<p>Username not found.</p>"
        html += '<p><a href="/login">Try Again</a></p>'
        return html
    
    password_hash = hash_password(password)
    if password_hash != user[0]:
        html = "<h1>Login Failed</h>"
        html += "<p>Incorrect password.</p>"
        html += '<p><a href="/login">Try Again</a></p>'
        return html
    
    session['username'] = username
    html = "<h1>Login Successful!</h1>"
    html += f"<p>Welcome back, {username}!</p>"
    html += '<p>You are now logged in.</p>'
    html += '<p><a href="/">Go to Dashboard</a></p>'
    return html

@app.route('/logout')
def logout():
    session.pop('username', None)
    html = "<h1>Logged Out</h1>"
    html += "<p>You have been successfully logged out.</p>"
    html += '<p><a href="/login">Login Again</a></p>'
    return html

@app.route('/export_csv')
def export_csv():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name, location, amount FROM customers")
    customers = cursor.fetchall()
    conn.close()

    import io
    from flask import send_file

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'Location', 'Amount'])
    writer.writerows(customers)

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='customers.csv'
    )


# Start web application
if __name__ == '__main__':
    app.run(debug=True, port=8080)