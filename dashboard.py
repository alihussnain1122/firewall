### Phase 4: Monitoring Dashboard ###

# This module implements a simple dashboard for visualizing the WAF activities.
# Flask is used to create the web UI for monitoring traffic, viewing blocked requests, etc.

from flask import Flask, render_template, request
import sqlite3
import os

# Step 1: Setup Flask Dashboard App
app = Flask(__name__)

db_file = "waf_logs.db"

# Step 2: Initialize SQLite Database
def init_db():
    if not os.path.exists(db_file):
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE logs (id INTEGER PRIMARY KEY, request TEXT, status TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
        conn.close()

# Step 3: Endpoint for Viewing Logs
@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', rows=rows)

# Step 4: Logging Functionality (called by the core WAF during request processing)
def log_request(request_data, status):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (request, status) VALUES (?, ?)", (request_data, status))
    conn.commit()
    conn.close()

# Example Endpoint for Testing the Dashboard
@app.route('/test', methods=['GET', 'POST'])
def test():
    if request.method == 'POST':
        log_request(request.get_data(as_text=True), "Blocked")
        return "Test log added!"
    return render_template('test.html')

# Run the Dashboard
if __name__ == '__main__':
    init_db()
    app.run(port=8081, debug=True)

### Note ###
# A corresponding HTML file named 'dashboard.html' should be created in a 'templates' folder.
# This HTML file should iterate through the 'rows' data and render the logs in a table format.
