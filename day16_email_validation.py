# Day 6 FIXED: Web Application Foundations
from flask import Flask, request, session, send_file, flash, redirect, url_for, render_template
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

def initialize_age_column():
    """Add age column to customers table and populate with sample data"""
    conn = get_database_connection()
    cursor = conn.cursor()

    # Add age column if it doesn't exist
    try:
        cursor.execute("ALTER TABLE customers ADD COLUMN age INTEGER")
        conn.commit()
        print("✅ Age column added to customers table.")
    except:
        print("ℹ️ Age column already exists.")

    # Update existing customers with sample ages
    cursor.execute("UPDATE customers SET age = 34 WHERE name = 'Lisa'")
    cursor.execute("UPDATE customers SET age = 52 WHERE name = 'Chris'")
    cursor.execute("UPDATE customers SET age = 42 WHERE name = 'Mike'")
    cursor.execute("UPDATE customers SET age = 28 WHERE name = 'Sarah'")
    cursor.execute("UPDATE customers SET age = 29 WHERE name = 'Sade'")
    cursor.execute("UPDATE customers SET age = 38 WHERE name = 'Jackson'")
    conn.commit()
    conn.close()

def initialize_purchase_date_column():
    """Add purchase_date column to customers table and populate with sample data"""
    conn = get_database_connection()
    cursor = conn.cursor()

    # Add purchase_date column if it doesn't exist
    try:
        cursor.execute("ALTER TABLE customers ADD COLUMN purchase_date TEXT")
        conn.commit()
        print("✅ Purchase date column added to customers table.")
    except:
        print("ℹ️ Purchase date column already exists.")

    # Update existing customers with sample purchase dates
    cursor.execute("UPDATE customers SET purchase_date = '2024-03-15' WHERE name = 'Lisa'")
    cursor.execute("UPDATE customers SET purchase_date = '2024-06-20' WHERE name = 'Chris'")
    cursor.execute("UPDATE customers SET purchase_date = '2024-01-10' WHERE name = 'Mike'")
    cursor.execute("UPDATE customers SET purchase_date = '2024-11-05' WHERE name = 'Sarah'")
    cursor.execute("UPDATE customers SET purchase_date = '2024-08-22' WHERE name = 'Sade'")
    cursor.execute("UPDATE customers SET purchase_date = '2024-09-30' WHERE name = 'Jackson'")
    conn.commit()
    conn.close()

def initialize_email_column():
    """Add email column to customers table and populate with sample data"""
    conn = get_database_connection()
    cursor = conn.cursor()

    # Add email column if it doesn't exist (Day 16)
    try:
        cursor.execute("ALTER TABLE customers ADD COLUMN email TEXT")
        conn.commit()
        print("✅ Email column added to customers table.")
    except sqlite3.OperationalError:
        # Column already exists
        print("ℹ️ Email column already exists.")

    # Update existing customers with sample email 
    cursor.execute("UPDATE customers SET email = 'lisa@email.com' WHERE name = 'Lisa'")
    cursor.execute("UPDATE customers SET email = 'chris@email.com' WHERE name = 'Chris'")
    cursor.execute("UPDATE customers SET email = 'sarah@email.com' WHERE name = 'Sarah'")
    cursor.execute("UPDATE customers SET email = 'sade@email.com' WHERE name = 'Sade'")
    cursor.execute("UPDATE customers SET email = 'jackson@email.com' WHERE name = 'Jackson'")
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

def initialize_inventory_column():
    """Add inventory column to products table and populate with sample data"""
    conn = get_database_connection()
    cursor = conn.cursor()

    # Add inventory column if it doesn't exist
    try:
        cursor.execute("ALTER TABLE products ADD COLUMN inventory INTEGER")
        conn.commit()
        print("✅ Inventory column added to products table.")
    except:
        print("ℹ️ Inventory column already exists.")

    # Update existing products with inventory values
    cursor.execute("UPDATE products SET inventory = 5 WHERE name = 'Laptop'")
    cursor.execute("UPDATE products SET inventory = 12 WHERE name = 'Monitor'")
    cursor.execute("UPDATE products SET inventory = 8 WHERE name = 'Keyboard'")
    cursor.execute("UPDATE products SET inventory = 50 WHERE name = 'Mouse'")
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

def calculate_average_age():
    conn = get_database_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT age FROM customers WHERE age IS NOT NULL")
    results = cursor.fetchall()
    conn.close()

    # Only include customers who have an age
    ages = [row[0] for row in results]

    # Return 0 if no customers have ages
    if len(ages) == 0:
        return 0

    average_age = sum(ages) // len(ages) 

    return int(average_age)

def calculate_revenue_by_date_range(start_date, end_date):
    """Calculate total revenue between two dates"""
    conn = get_database_connection()
    cursor = conn.cursor()

    # SQL query to get revenue between dates
    cursor.execute("""
        SELECT SUM(amount)
        FROM customers
        WHERE purchase_date BETWEEN ? AND ?
    """, (start_date, end_date))

    result = cursor.fetchone()[0]
    conn.close()

    # Return 0 if no purchases in that range
    return result if result else 0

def get_location_statistics():
    """Get customer count, total revenue, and average spending per location"""
    conn = get_database_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT location,
                COUNT(*) as customer_caount,
                SUM(amount) as total_revenue,
                AVG(amount) as avg_spending
        FROM customers
        GROUP BY location
        ORDER BY total_revenue DESC
    """)
    results = cursor.fetchall()
    conn.close()

    # Convert to list of dictionaries for easier use
    stats = []
    for row in results:
        stats.append({
            'location': row[0],
            'customer_count': row[1],
            'total_revenue': row[2],
            'avg_spending': row[3]
        })

    return stats

def test_customer_ranking():
    print("\n=== CUSTOMER RANKING TEST ===")
    ranked = rank_customers_by_composite_score()
    for i, customer in enumerate(ranked, 1):
        print(f"#{i}: {customer['name']} - Amount: ${customer['amount']}, Loyalty: {customer['loyalty']}, Score: {customer['score']:.1f}")

def test_average_age():
    print("\n=== AVERAGE AGE TEST ===")
    avg_age = calculate_average_age()
    print(f"Average customer age: {avg_age} years")



def test_loyalty_points():
    print("\n=== LOYALTY POINTS TEST ===")
    test_customers = ["Sarah", "Chris", "Sade", "Lisa"]
    for name in test_customers:
        points = calculate_loyalty_points(name)
        print(f"{name}: {points} loyalty points")


def test_email_column():
    """Verify email column exists and show current email values"""
    conn = get_database_connection()
    cursor = conn.cursor()

    # Check if email column exists by selecting from it
    cursor.execute("SELECT name, email FROM customers")
    customers = cursor.fetchall()
    conn.close()

    print("\n=== EMAIL COLUMN TEST ===")
    print(f"Total customers with email field: {len(customers)}")
    for customer in customers:
        email_status = customer[1] if customer[1] else "None (NULL)"
        print(f"  {customer[0]}: {email_status}")

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
initialize_inventory_column()
initialize_age_column()
initialize_purchase_date_column()
initialize_email_column()
initialize_users_table()
test_password_hashing()
test_users_table()
test_loyalty_points()
test_customer_ranking()
test_average_age()
test_email_column()



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
    html += '<a href="/search_location" style="margin-right: 15px; color: blue;">Location Search</a>'
    html += '<a href="/sorted_customers" style="margin-right: 15px; color: blue;">Sorted Customers</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/export_csv" style="margin-right: 15px; color: blue;">Export CSV</a>'
    html += '<a href="/revenue_report" style="margin-right: 15px; color: blue;">Revenue Report</a>'
    html += '<a href="/export_excel" style="margin-right: 15px; color: blue;">Export Excel</a>'
    html += '<a href="/location_stats" style="margin-right: 15px; color: blue;">Location Stats</a>'
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
    customers = [{'id': row[0], 'name': row[1], 'location': row[2], 'amount': row[3], 'email': row[6]}
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
    html += '<a href="/search_location" style="margin-right: 15px; color: blue;">Location Search</a>'
    html += '<a href="/sorted_customers" style="margin-right: 15px; color: blue;">Sorted Customers</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/export_csv" style="margin-right: 15px; color: blue;">Export CSV</a>'
    html += '<a href="/revenue_report" style="margin-right: 15px; color: blue;">Revenue Report</a>'
    html += '<a href="/export_excel" style="margin-right: 15px; color: blue;">Export Excel</a>'
    html += '</nav>'
    
    for customer in customers:
        email_display = customer['email'] if customer['email'] else 'No email'
        html += f"<p>Customer: {customer['name']} ({customer['location']}) - ${customer['amount']} - Email: {email_display} "
        html += f"<a href='/edit_customer/{customer['id']}'>[Edit]</a> "
        html += f"<a href='/delete_customer/{customer['id']}' onclick=\"return confirm('Are you sure you want to delete {customer['name']}?');\">[Delete]</a></p>"
    
    html += '<p><a href="/">Back to Dashboard</a></p>'
    # Add new customer form
    html += "<h2>Add New Customer:</h2>"
    html += '<form method="POST" action="/add_customer">'
    html += '<input type="text" name="customer_name" placeholder="Customer Name" required>'
    html += '<input type="text" name="customer_location" placeholder="Location" required>'
    html += '<input type="number" name="customer_amount" placeholder="Purchase Amount" required>'
    html += '<input type="email" name="customer_email" placeholder="Email Address" required>'
    html += '<input type="number" name="customer_age" placeholder="Age" required>'
    html += '<button type="submit">Add Customer</button>'
    html += '</form>'

    return html

@app.route('/products')
def products_page():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products")
    all_products = [{'id': row[0], 'name': row[1], 'revenue': row[2], 'units': row[3], 'inventory': row[4]}
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
    html += '<a href="/search_location" style="margin-right: 15px; color: blue;">Location Search</a>'
    html += '<a href="/sorted_customers" style="margin-right: 15px; color: blue;">Sorted Customers</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/revenue_report" style="margin-right: 15px; color: blue;">Revenue Report</a>'
    html += '<a href="/export_csv" style="margin-right: 15px; color: blue;">Export CSV</a>'
    html += '</nav>'

    for product in all_products:
        inventory = product['inventory']
        warning = "🚨 LOW STOCK!" if inventory < 10 else ""
        html += f"<p>{warning} Product: {product['name']} - Revenue: ${product['revenue']} - Units Sold: {product['units']} - Inventory: {inventory}</p>"
        html += f"<a href='/restock_product/{product['id']}'>[Restock]</a></p>"
    
    return html

@app.route('/restock_product/<int:product_id>')
def restock_product(product_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    conn.close()

    return render_template('restock_product.html', product=product)

@app.route('/process_restock/<int:product_id>', methods=['POST'])
def process_restock(product_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    add_quantity = int(request.form.get('add_quantity'))

    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE products SET inventory = inventory + ? WHERE id = ?',
                   (add_quantity, product_id))
    conn.commit()
    conn.close()

    return redirect(url_for('products_page'))

@app.route('/add_customer', methods=['POST'])
def add_customer():
    if 'username' not in session:
        flash('Please log in to access this page', 'error')
        return redirect(url_for('login'))
    # Get form data
    name = request.form.get('customer_name', '').strip()
    location = request.form.get('customer_location', '').strip()
    
    try:
        amount = int(request.form.get('customer_amount', 0))
    except ValueError:
        amount = -1  # Force validation error for non-numeric input

    # Get email from form
    email = request.form.get('customer_email', '').strip()

    # GEt age from form
    try:
        age = int(request.form.get('customer_age', 0))
    except ValueError:
        age = 0

    # Validate the data
    errors = validate_customer_data(name, location, amount)

    # Validate email format
    if not validate_email(email):
        errors.append("Invalid email format. Must be like: name@domain.com")
    
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
        cursor.execute("INSERT INTO customers (name, location, amount, email, age) VALUES (?, ?, ?, ?, ?)",
                       (name, location, amount, email, age))
        conn.commit()
        conn.close()

        html = "<h1>Customer Added Successfully!</h1>"
        html += f"<p>New Customer: {name} from {location} - ${amount} - Email: {email}</p>"
        html += '<p><a href="/customers">Back to Customers</a></p>'
    
    return html

@app.route('/edit_customer/<int:customer_id>', methods=['GET', 'POST'])
def edit_customer(customer_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()

    if request.method == 'GET':
        # fetch the customer's current data
        cursor.execute('SELECT * FROM customers WHERE id = ?', (customer_id,))
        customer = cursor.fetchone()
        conn.close()
        return render_template('edit_customer.html', customer=customer)
    
    else: # POST request - update the customer
        name = request.form.get('name')
        location = request.form.get('location')
        amount = int(request.form.get('amount'))

        cursor.execute('UPDATE customers SET name = ?, location = ?, amount = ? WHERE id = ?',
                          (name, location, amount, customer_id))
        conn.commit()
        conn.close()

        return redirect(url_for('home'))

@app.route('/delete_customer/<int:customer_id>')
def delete_customer(customer_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM customers WHERE id = ?', (customer_id,))
    conn.commit()
    conn.close()
    
    return redirect(url_for('customers_page'))

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
    html += '<a href="/export_excel" style="margin-right: 15px; color: blue;">Export Excel</a>'
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

@app.route('/search_location', methods=['GET', 'POST'])
def search_location():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    html = "<h1>Search Customers by Location</h1>"
    html += '<nav style="background-color: #f0f0f0; padding: 10px; margin-bottom: 20px;">'
    html += '<a href="/" style="margin-right: 15px; color: blue;">Dashboard</a>'
    html += '<a href="/customers" style="margin-right: 15px; color: blue;">All Customers</a>'
    html += '<a href="/search_location" style="margin-right: 15px; color: blue;">Location Search</a>'
    html += '</nav>'
    html += '<h2>Enter Location to Search:</h2>'
    html += '<form method="POST">'
    html += '<input type="text" name="location" placeholder="Enter city (e.g., Houston)" required>'
    html += '<button type="submit">Search Location</button>'
    html += '</form>'

    # If form was submitted (POST request), show results
    if request.method == 'POST':
        location = request.form.get('location')

        conn = get_database_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name, amount FROM customers WHERE location = ?", (location,))
        results = cursor.fetchall()
        conn.close()

        html += f"<h2>Customers in {location}:</h2>"
        if results:
            total_revenue = 0
            for customer in results:
                html += f"<p>Customer: {customer[0]} - ${customer[1]}</p>"
                total_revenue += customer[1]

            html += f"<p><strong>Total: {len(results)} customers, ${total_revenue} revenue</strong></p>"
        else:
            html += f"<p>No customers found in {location}.</p>"
        
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
    html += '<a href="/revenue_report" style="margin-right: 15px; color: blue;">Revenue Report</a>'
    html += '<a href="/export_excel" style="margin-right: 15px; color: blue;">Export Excel</a>'
    html += '</nav>'
    
    for customer in sorted_list:
        html += f"<p>#{sorted_list.index(customer)+1}: {customer['name']} - ${customer['amount']} ({customer['location']})</p>"
    
    return html


@app.route('/analytics')
def analytics_page():
    if 'username' not in session:
        flash('Please log in to access this page', 'error')
        return redirect(url_for('login'))
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

    # Calculate average age (Feature 1)
    avg_age = calculate_average_age()
    
    html = "<h1>Business Analytics Dashboard</h1>"
    html += '<nav style="background-color: #f0f0f0; padding: 10px; margin-bottom: 20px;">'
    html += '<a href="/" style="margin-right: 15px; color: blue;">Dashboard</a>'
    html += '<a href="/customers" style="margin-right: 15px; color: blue;">All Customers</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/sorted_customers" style="margin-right: 15px; color: blue;">Sorted Customers</a>'
    html += '<a href="/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/search_location" style="margin-right: 15px; color: blue;">Location Search</a>'
    html += '<a href="/export_csv" style="margin-right: 15px; color: blue;">Export CSV</a>'
    html += '<a href="/revenue_report" style="margin-right: 15px; color: blue;">Revenue Report</a>'
    html += '<a href="/export_excel" style="margin-right: 15px; color: blue;">Export Excel</a>'
    html += '</nav>'
    
    html += f"<p><strong>Total Customers:</strong> {stats['count']}</p>"
    html += f"<p><strong>Total Revenue:</strong> ${stats['total']}</p>"
    html += f"<p><strong>Average Purchase:</strong> ${stats['mean']}</p>"
    html += f"<p><strong>Median Purchase:</strong> ${stats['median']}</p>"
    html += f"<p><strong>Average Customer Age:</strong> {avg_age} years</p>"
    
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
    if 'username' not in session:
        flash('Please log in to access this page', 'error')
        return redirect(url_for('login'))
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

@app.route('/export_excel')
def export_excel():
    if 'username' not in session:
        flash('Please log in to access this page', 'error')
        return redirect(url_for('login'))
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
        mimetype='application/vnd.ms-excel',
        as_attachment=True,
        download_name='customers.xls'
    )

@app.route('/revenue_report', methods=['GET', 'POST'])
def revenue_report():
    if 'username' not in session:
        flash('Please log in to access this page', 'error')
        return redirect(url_for('login'))
    
    html = "<h1>Revenue by Date Range</h1>"
    html += '<nav style="background-color: #f0f0f0; padding: 10px; margin-bottom: 20px;">'
    html += '<a href="/" style="margin-right: 15px; color: blue;">Dashboard</a>'
    html += '<a href="/customers" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/revenue_report" style="margin-right: 15px; color: blue;">Revenue Report</a>'
    html += '<a href="/search_location" style="margin-right: 15px; color: blue;">Location Search</a>'
    html += '</nav>'

    # Show the date filter form
    html += '<h2>Calculate Revenue by Date Range:</h2>'
    html += '<form method="POST">'
    html += '<label>Start Date: <input type="date" name="start_date" required></label><br><br>'
    html += '<label>End Date: <input type="date" name="end_date" required></label><br><br>'
    html += '<button type="submit">Calculate Revenue</button>'
    html += '</form>'

    # If form was submitted, calculate and display results
    if request.method == 'POST':
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')

        total_revenue = calculate_revenue_by_date_range(start_date, end_date)

        html += '<h2>Results:</h2>'
        html += f'<p><strong>Revenue from {start_date} to {end_date}: ${total_revenue}</strong></p>'

    return html

@app.route('/location_stats')
def location_stats():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Get location statistics
    stats = get_location_statistics()

    html = "<h1>Location Statistics</h1>"
    html += '<style>'
    html += 'body { font-famile: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }'
    html += 'h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }'
    html += '</style>'
    html += '<nav style="background-color: #f0f0f0; padding: 10px; margin-bottom: 20px;">'
    html += '<a href="/customers" style="margin-right: 15px; color: blue;">All Customers</a>'
    html += '<a href+"/analytics" style="margin-right: 15px; color: blue;">Analytics</a>'
    html += '<a href="/location_stats" style="margin-right: 15px; color: blue;">Location Stats</a>'
    html += '<a href="/search_location" style="margin-right: 15px; color: blue;">Location Search</a>'
    html += '</nav>'

    html += "<h2>Revenue and Customer Breakdown by Location:</h2>"

    for stat in stats:
        html += f"<p><strong>{stat['location']}:</strong> "
        html += f"{stat['customer_count']} customers - "
        html += f"${stat['total_revenue']} total revenue - "
        html += f"${stat['avg_spending']:.2f} average spending</p>"

    html += '<p><a href="/">Back to Dashboard</a></p>'
    return html


# Start web application
if __name__ == '__main__':
    # DEBUG: Print all users before starting server
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users")
    all_users = cursor.fetchall()
    conn.close()
    print("\n=== ALL REGISTERED USERS ===")
    for user in all_users:
        print(f"Username: '{user[0]}'")
    print("=============================\n")

    app.run(debug=True, port=8080)
