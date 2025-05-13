# PHP Vulnerability Scanner

This is a PHP vulnerability scanner designed to identify common security vulnerabilities such as XSS, SQLi, RCE, and others, using regular expressions.

## Features

- Scans PHP files to identify security vulnerabilities.
- Detects various types of vulnerabilities, including:
  - **XSS (Cross-Site Scripting)**
  - **Eval**
  - **SQLi (SQL Injection)**
  - **RCE (Remote Code Execution)**
  - **LFI/RFI (Local/Remote File Inclusion)**
  - **File Operations**
  - **Unserialize**
  - **Deprecated**
  - **Dynamic Code**
  - **Info Leak**
  - **Security Misconfiguration**
  - **Session Fixation**
  - **Header Injection**
  - **Manual Deserialization**
  - **Insecure Random**
  - **Weak Hashing**
  - **Open Redirect**
  - **Dynamic Class Instantiation**
  - **Verbose Errors**
  - **Globals Misuse**
  - **Hardcoded Secrets / Path**
  - **No verification**
  - **Regex Problem**
  - **PowerShell Commands**


## Requirements

- Python 3.x
- Python Libraries:
  - `re` (included in Python by default)
  - `os` (included in Python by default)
  - `argparse` (included in Python by default)

## Installation

1. Clone the repository:

```
git clone https://github.com/srliath/vuln-scan
cd vuln-scan
```


2. (Optional) Create a virtual environment to isolate the project dependencies:

```
python3 -m venv venv
source venv/bin/activate # On Linux/Mac
venv\Scripts\activate # On Windows
```

## How to Use

Run the Python script, passing the paths of the PHP files or directories to scan:


```
python scanner.py <path_to_php_files_or_directories>
```

### Example:

```
python scanner.py /var/www/html /home/user/project/index.php
python scanner.py /var/www/html /home/user/
```

The scanner will search the provided files and directories for known vulnerabilities using predefined regular expressions.

## Output Format

The output will be a list of detected vulnerabilities, including the file name, line number, line content, and the type of vulnerability found:

```
[
{
"file": "/path/to/file.php",
"line_number": 42,
"line": "echo $_GET['user'];",
"vuln_type": "XSS"
},
{
"file": "/path/to/file.php",
"line_number": 89,
"line": "eval($_GET['code']);",
"vuln_type": "Eval"
}
]
```


## Contributing

1. Fork this repository.
2. Create a branch for your changes (`git checkout -b feature/new-vulnerability`).
3. Commit your changes (`git commit -am 'Add new vulnerability'`).
4. Push to the remote repository (`git push origin feature/new-vulnerability`).
5. Open a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
