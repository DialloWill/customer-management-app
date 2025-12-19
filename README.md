 Customer Management Web Application

A full-stack customer management system built with Python, Flask, and SQLite. This project demonstrates my ability to build secure, functional web applications with user authentication, database design, and business analytics.

🎥 [Watch Video Demo] (https://youtu.be/cs8m9sUQCxw) - Full walktrhough of features

---

 🚀 Key Features

User Authentication & Security
- Secure login/logout system with SHA-256 password hashing
- Session management with Flask sessions
- Protected routes requiring authentication
- Input validation and SQL injection prevention

Customer & Product Management
- Add, view, edit, and delete customer records
- Product inventory tracking
- Relational database design with normalized tables

Business Analytics Dashboard
- Real-time analytics: customer count, total revenue, average order value
- Statistical calculations (median, sum, count)
- Data visualization of key metrics

Data Export & Reporting
- Export customer data to CSV format
- Automated report generation
- Search and filter functionality

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

---

 📊 Database Schema

The application uses three normalized tables:

Users Table
- user_id (Primary Key)
- username
- password_hash
- created_at

Customers Table
- customer_id (Primary Key)
- name
- email
- phone
- created_at

Products Table
- product_id (Primary Key)
- product_name
- price
- quantity

---

 🔧 Installation & Setup

```bash
 Clone the repository
git clone https://github.com/DialloWill/customer-management-app.git
cd customer-management-app

 Install dependencies
pip install flask

 Run the application
python day10_authentication_export_mastery.py

 Access at http://localhost:5000
```

Default Login Credentials** (for testing):
- Username: `admin`
- Password: `admin123`

---

 📸 Screenshots

(Screenshots to be added)

---

 🚧 Future Enhancements

- Add password reset functionality
- Implement email notifications
- Add data visualization charts (Matplotlib/Plotly)
- Deploy to cloud platform (Heroku/Railway)
- Add pagination for large datasets
- Implement advanced search with multiple filters

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

