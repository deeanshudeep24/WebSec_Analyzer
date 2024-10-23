# WebSec Analyzer

WebSec Analyzer is a Python-based tool for scanning websites to detect common security vulnerabilities. It performs checks for SQL Injection, XSS vulnerabilities, directory traversal, missing security headers, SSL certificate validation, and port scanning (using Nmap).

## Features

- **SQL Injection Detection**: Identifies vulnerabilities that allow malicious SQL queries.
- **Cross-Site Scripting (XSS) Detection**: Checks for XSS vulnerabilities in web forms.
- **Directory Traversal Check**: Scans for sensitive directories and files.
- **Security Headers Check**: Ensures essential security headers are present.
- **SSL Certificate Validation**: Verifies the validity of SSL certificates.
- **Port Scanning**: Uses Nmap to detect open network ports (optional).

## Installation

### Prerequisites

Before running this tool, ensure that you have:

- **Python 3.x**
- **Nmap** (for port scanning)

You can install Nmap using:

- **Windows**: [Download from Nmap official site](https://nmap.org/download.html)
- **Linux**: `sudo apt-get install nmap`
- **macOS**: `brew install nmap`

### Installing Dependencies

To install the required Python libraries, run:

```bash
pip install -r requirements.txt
