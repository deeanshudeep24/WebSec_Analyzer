import requests
from bs4 import BeautifulSoup
import socket
import ssl
import nmap

# Welcome message
def welcome_message():
    print("***************************************")
    print("*   Welcome to WebSec Analyzer v1.0   *")
    print("*   Program written by Deepanshu Deep *")
    print("***************************************\n")
    print("This tool helps you scan websites for common security vulnerabilities.\n")

# SQL Injection payloads
sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 'a'='a"]

# Directory traversal paths
common_paths = ["/admin", "/login", "/config", "/.git/", "/.env"]

# SQL Injection Check
def check_sql_injection(url):
    print("\n[+] Checking for SQL Injection vulnerabilities...")
    for payload in sql_payloads:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url)
            if "SQL" in response.text or "syntax" in response.text:
                print(f"[!] SQL Injection Vulnerability found at: {test_url}")
                return
        except requests.RequestException:
            print("[-] Failed to reach the site for SQL Injection testing.")
    print("[-] No SQL Injection Vulnerability found.")

# XSS Check
def check_xss(url):
    print("\n[+] Checking for Cross-Site Scripting (XSS) vulnerabilities...")
    xss_payload = "<script>alert(1)</script>"
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            full_url = url + action if action else url
            response = requests.post(full_url, data={"input": xss_payload})
            if xss_payload in response.text:
                print(f"[!] XSS Vulnerability found in form action: {action}")
                return
    except requests.RequestException:
        print("[-] Failed to reach the site for XSS testing.")
    print("[-] No XSS Vulnerability found.")

# Directory Traversal Check
def check_directory_traversal(url):
    print("\n[+] Checking for open directories or sensitive paths...")
    for path in common_paths:
        full_url = url + path
        try:
            response = requests.get(full_url)
            if response.status_code == 200:
                print(f"[!] Directory or sensitive file found at: {full_url}")
            else:
                print(f"[-] No access to: {full_url}")
        except requests.RequestException:
            print(f"[-] Failed to reach the site for path: {full_url}")

# Security Headers Check
def check_headers(url):
    print("\n[+] Checking for missing security headers...")
    try:
        response = requests.head(url)
        missing_headers = []
        if "X-Frame-Options" not in response.headers:
            missing_headers.append("X-Frame-Options")
        if "Content-Security-Policy" not in response.headers:
            missing_headers.append("Content-Security-Policy")
        if "X-Content-Type-Options" not in response.headers:
            missing_headers.append("X-Content-Type-Options")

        if missing_headers:
            print(f"[!] Missing security headers: {', '.join(missing_headers)}")
        else:
            print("[-] All essential security headers are present.")
    except requests.RequestException:
        print("[-] Failed to check security headers.")

# SSL Certificate Validation
def check_ssl_certificate(url):
    print("\n[+] Checking SSL certificate...")
    try:
        hostname = url.replace('https://', '').replace('http://', '').split('/')[0]
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        if cert:
            print(f"[-] SSL certificate is valid for {hostname}")
        else:
            print(f"[!] No valid SSL certificate for {hostname}")
    except Exception as e:
        print(f"[!] Error checking SSL certificate: {e}")

# Port Scanning using nmap (optional)
def scan_ports(url):
    print("\n[+] Scanning for open ports using nmap...")
    hostname = url.replace('https://', '').replace('http://', '').split('/')[0]
    nm = nmap.PortScanner()
    try:
        nm.scan(hostname, '1-1024')
        for host in nm.all_hosts():
            print(f"Host: {host}")
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    print(f"Port {port} is {state}")
    except Exception as e:
        print(f"[!] Error during port scanning: {e}")

# Function to get user's choices
def get_user_choices():
    print("\nWhat would you like to do?")
    print("1. Check for SQL Injection vulnerabilities")
    print("2. Check for XSS vulnerabilities")
    print("3. Check for open directories/sensitive files")
    print("4. Check for missing security headers")
    print("5. Check SSL certificate validity")
    print("6. Scan for open ports using nmap")
    print("7. Perform all checks")
    
    choices = input("\nEnter the numbers of the tasks you want to perform (comma-separated, e.g., 1,3,5): ")
    return [int(choice.strip()) for choice in choices.split(",") if choice.strip().isdigit()]

if __name__ == "__main__":
    welcome_message()  # Display the welcome message
    
    target_url = input("Enter the target website URL: ").strip()
    
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url
    
    tasks = get_user_choices()

    # Execute tasks based on user choice
    if 1 in tasks or 7 in tasks:
        check_sql_injection(target_url)
    if 2 in tasks or 7 in tasks:
        check_xss(target_url)
    if 3 in tasks or 7 in tasks:
        check_directory_traversal(target_url)
    if 4 in tasks or 7 in tasks:
        check_headers(target_url)
    if 5 in tasks or 7 in tasks:
        check_ssl_certificate(target_url)
    if 6 in tasks or 7 in tasks:
        scan_ports(target_url)
