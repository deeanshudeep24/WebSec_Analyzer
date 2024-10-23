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
```
## Usage

1. Run the script using:
   ```bash
   python websec_analyzer.py
   ```

2. Enter the target website URL.

3. Choose from the options to perform specific checks or all checks.

## Example Output

```bash
***************************************
*   Welcome to WebSec Analyzer v1.0   *
*   Program written by Deepanshu Deep *
***************************************

Enter the target website URL: https://example.com
What would you like to do?
1. Check for SQL Injection vulnerabilities
2. Check for XSS vulnerabilities
3. Check for open directories/sensitive files
4. Check for missing security headers
5. Check SSL certificate validity
6. Scan for open ports using nmap
7. Perform all checks

Enter the numbers of the tasks you want to perform (comma-separated, e.g., 1,3,5): 1,4,5
```

## License

This project is licensed under the MIT License.
```

This provides a clear and concise description of your project with installation, usage, and example output details.
```















