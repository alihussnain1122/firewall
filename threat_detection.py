# threat_detection.py

import re

def is_malicious_request(data):
    """
    An advanced implementation for detecting malicious payloads.
    :param data: str
    :return: boolean
    """
    # Detect SQL Injection patterns using enhanced regex
    sql_injection_patterns = [
        r"(?i)(\\bor\\b|\\band\\b)[^\\w]*[\\'\\\"]",
        r"(?i)(union select|select\\s*\\*|drop table|insert into|delete from)",
        r"(?i)(--|#|\\/\\*|\\*\\/|;)",  # SQL comments and statement terminators
    ]
    
    # Detect XSS patterns using regex
    xss_patterns = [
        r"<script.*?>.*?<\\/script.*?>",
        r"(?i)javascript:",
        r"<.*?on\\w+\\s*=\\s*['\\\"]",
    ]

    # Check if the data matches any of the patterns
    for pattern in sql_injection_patterns + xss_patterns:
        if re.search(pattern, data):
            return True
    return False

# Print to confirm the module loaded properly
print("threat_detection module loaded")
