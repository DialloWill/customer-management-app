 Customer Management Web Application

A full-stack customer management system built with Python, Flask, and SQLite. This project demonstrates my ability to build secure, functional web applications with user authentication, database design, and business analytics.

🎥 [Watch Video Demo] (https://youtu.be/cs8m9sUQCxw) - Full walktrhough of features
*Note: This is a visual demonstration. The app features are also documented in detail below.*

---
 ✨ Key Features

 🔐 Security & Authentication
- User registration and login system
- SHA-256 password hashing
- Session management with Flask sessions
- Protected routes (login required for sensitive operations)

 👥 Customer Management (Full CRUD)
- Create: Add new customers with validation
- Read: View all customers with detailed information
- Update: Edit customer details (name, location, amount)
- Delete: Remove customers with confirmation
- Email validation (regex pattern matching)
- Age tracking and analytics

 📊 Business Analytics Dashboard
- Real-time metrics: total customers, revenue, average purchase
- VIP customer identification with customizable threshold
- Customer ranking by composite score (spending + loyalty points)
- Average customer age calculation
- Location-based revenue statistics

 📦 Product & Inventory Management
- Product performance tracking (revenue, units sold)
- Real-time inventory monitoring
- Low stock alerts (< 10 units)
- Restock functionality

 🔍 Advanced Search & Filtering
- Search customers by name (linear search algorithm)
- Filter customers by location
- Location statistics (customer count, total revenue, avg spending)
- Revenue reports by date range

 📈 Data Export & Reporting
- Export customer data to CSV
- Export to Excel format (.xls)
- Automated report generation
- Revenue analysis by date range

 🗄️ Database Design
- SQLite database with 3 normalized tables:
  - **customers**: id, name, location, amount, age, email, purchase_date
  - **products**: id, name, revenue, units, inventory
  - **users**: id, username, password_hash
- Prevents SQL injection with parameterized queries

---

 🛠️ Technical Stack

Backend
- Python 3.x
- Flask web framework
- SQLite database
- SQL queries for data operations

Frontend
- HTML5/CSS3
- Jinja2 templating engine
- Responsive design

Security
- SHA-256 password hashing
- Session-based authentication
- Secure route protection
- Input sanitization

---

💡 What I Learned

This project strengthened my understanding of:
- Full-stack web application architecture
- RESTful routing and HTTP methods (GET, POST)
- Database design with normalized tables (customers, products, users)
- User authentication flow and session management
- SQL queries and database operations (SELECT, INSERT, UPDATE, DELETE)
- Form handling and data validation
- Business logic implementation (analytics calculations)
- Form handling, data validation, and input sanitization (regex, email validation)
- CRUD operations implementation in web applications

---

 📊 Database Schema

The application uses three normalized tables:

Users Table
- id (Primary Key, Auto-increment)
- username (Unique)
- password_hash (SHA-256)

Customers Table
- id (Primary Key, Auto-increment)
- name
- location
- amount (purchase amount)
- age
- email
- purchase_date

Products Table
- id (Primary Key, Auto-increment)
- name
- revenue
- units (units sold)
- inventory (stock quantity)
---

 🔧 Installation & Setup

```bash
 Clone the repository
git clone https://github.com/DialloWill/customer-management-app.git
cd customer-management-app

 Install dependencies
pip install flask

# Run the application
python day16_email_validation.py

# Access at http://localhost:8080
```

Default Login Credentials** (for testing):
- Username: `admin`
- Password: `admin123`

---

 📸 Demo
   
   🎥 **[Watch Full Video Demo](https://youtu.be/cs8m9sUQCxw)** - See all features in action

---

  🚧 Future Enhancements

- Password reset functionality via email
- Email notifications for low inventory alerts
- Data visualization charts (Matplotlib/Plotly)
- Advanced reporting (PDF export, custom date ranges)
- Pagination for large customer datasets
- Multi-user roles (admin, manager, viewer)
- API endpoints for external integrations
- Deploy to cloud platform (Heroku/Railway/AWS)

---

 📫 Contact

Diallo Williams  
Software Developer | Python & Flask  
📧 diallowill@gmail.com  
🔗 [LinkedIn](https://linkedin.com/in/diallowilliams)  
📍 Brooklyn, NY

Open to entry-level software development opportunities (remote or NYC-based).

---
 📄 License

This project is open source and available for educational purposes.

