### Integrated WAF Core with Threat Detection, ML Detection, and Logging ###

# This integrated core proxy combines rule-based detection, ML-based detection, and logging.

from flask import Flask, request, Response
import requests
import re
import sqlite3
import os
from threat_detection import is_malicious_request as rule_based_detection
from ml_detection import is_anomalous_request

# Step 1: Initial Setup
app = Flask(__name__)
backend_url = "http://localhost:5001"  # The backend server to which we will forward legitimate requests

db_file = "waf_logs.db"

# Step 2: Initialize SQLite Database
def init_db():
    if not os.path.exists(db_file):
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE logs (id INTEGER PRIMARY KEY, request TEXT, status TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
        conn.close()

# Step 3: Logging Functionality
def log_request(request_data, status):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (request, status) VALUES (?, ?)", (request_data, status))
    conn.commit()
    conn.close()

# Step 4: Reverse Proxy Endpoint
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    # Capture incoming request data
    request_data = request.get_data(as_text=True)

    # Step 4.1: Rule-based Threat Detection
    if request_data and rule_based_detection(request_data):
        log_request(request_data, "Blocked - Rule-based detection")
        return Response("Request blocked by WAF - Potential attack detected (rule-based).", status=403)

    # Step 4.2: ML-based Anomaly Detection
    features = [len(request_data), sum(1 for char in request_data if not char.isalnum())]
    if request_data and is_anomalous_request(features):
        log_request(request_data, "Blocked - ML-based detection")
        return Response("Request blocked by WAF - Potential attack detected (ML-based).", status=403)

    # Step 4.3: Forward legitimate requests to the backend server
    try:
        resp = requests.request(
            method=request.method,
            url=f"{backend_url}/{path}",
            headers={key: value for (key, value) in request.headers},
            data=request_data,
            cookies=request.cookies,
            allow_redirects=False)
        
        # Log allowed request
        log_request(request_data, "Allowed")
        
        # Return the backend server's response
        response = Response(resp.content, resp.status_code)
        for key, value in resp.headers.items():
            response.headers[key] = value
        return response
    except requests.exceptions.RequestException as e:
        # Handle backend connection errors gracefully
        return Response(f"Error connecting to backend server: {str(e)}", status=502)

# Step 5: Run the Application
if __name__ == '__main__':
    init_db()
    app.run(port=8080, debug=True, use_reloader=False)
