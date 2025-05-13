import os
import re
import argparse

patterns = {
    "XSS": [
        r'(?i)\b(echo|print)\s+(.*\$_(GET|POST|REQUEST|COOKIE)\[.*\])',
        r'(?i)\b(echo|print)\s+\$_(GET|POST|REQUEST|COOKIE)\b',
        r'(?i)\b(res\.send|console\.log)\s*\(\s*req\.(query|body|params)\[.*?\]\s*\)',
        r'(?i)\b(innerHTML|outerHTML)\s*=\s*.*\$_(GET|POST|REQUEST|COOKIE)\b',
    ],
    "Eval": [
        r'(?i)\beval\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bsetTimeout\s*\(\s*eval\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
    ],
    "SQLi": [
        r'(?i)\b(mysql_query|mysqli_query|pg_query|sqlite_query)\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bexecute\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bprepare\s*\(\s*".*?\$\w+.*?"\s*\)',
    ],
    "RCE": [
        r'(?i)\b(exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec|spawn|execSync|spawnSync)\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\beval\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bassert\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bcreate_function\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)`.*\$_(GET|POST|REQUEST|COOKIE).*?`',
        r'(?i)\beval\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bFunction\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\b(new\s+Function)\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bspawnSync\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bspawn\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bexecSync\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.exec\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.execSync\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.spawn\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.spawnSync\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.fork\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.forkSync\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.execFile\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.execFileSync\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.spawnFile\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.spawnFileSync\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.forkFile\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.forkFileSync\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.execFileSync\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.execSync\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bchild_process\.exec\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\b(require|import)\s*\(\s*["\'](child_process|vm2|eval5|sandboxjs)["\']\s*\)',
        
    ],
    "LFI/RFI": [
        r'(?i)\b(include|include_once|require|require_once)\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\b(include|include_once|require|require_once)\s*\(\s*"http[s]?://.*\$_(GET|POST|REQUEST|COOKIE).*?"\s*\)',
        r'(?i)\b(require|import)\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\b(require|import)\s*\(.*"http[s]?://.*\$_(GET|POST|REQUEST|COOKIE).*?"\)',
    ],
    "File Operations": [
        r'(?i)\b(file_get_contents|fopen|readfile|file_put_contents|fwrite|copy|rename|unlink|chmod|rmdir)\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bmove_uploaded_file\s*\(.*\$_FILES\[.*?\].*?,\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\b(fs\.readFileSync|fs\.writeFileSync|fs\.unlinkSync)\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bfs\.renameSync\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
    ],
    "Unserialize": [
        r'(?i)\bunserialize\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bjson_decode\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?,\s*true\s*\)',
    ],
    "Deprecated": [
        r'(?i)\bmysql_\w+\s*\(.*?\)',
        r'(?i)\b(ereg|ereg_replace|eregi|eregi_replace)\s*\(.*?\)',
        r'(?i)\b(set_magic_quotes_runtime|magic_quotes_gpc)\b',
    ],
    "Dynamic Code": [
        r'(?i)\bcall_user_func(?:_array)?\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\$\$\w+\s*=.*\$_(GET|POST|REQUEST|COOKIE)',
        r'(?i)\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\)',
        r'(?i)\b(Function)\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\b(new\s+Function)\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
    ],
    "Info Leak": [
        r'(?i)\bphpinfo\s*\(\s*\)',
        r'(?i)\b(var_dump|print_r)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION|ENV|FILES).*?\)',
        r'(?i)\b(console\.log|console\.error)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)\)',
        r'(?i)\bBearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\b',
    ],
    "Security Misconfig": [
        r'(?i)\bini_set\s*\(\s*["\'](allow_url_include|allow_url_fopen)["\']\s*,\s*["\']1["\']\s*\)',
        r'(?i)\berror_reporting\s*\(\s*E_ALL\s*\)',
        r'(?i)\bprocess\.env\s*\["(.*)"\]\s*=\s*["\'](.*)["\']',
        r'(?i)\bconsole\.warn\s*\(\s*process\.env\s*["\'](NODE_ENV|DEBUG|API_KEY)["\']\s*\)',
    ],
    "Session Fixation": [
        r'(?i)\bsession_id\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\)',
        r'(?i)\bsession_start\s*\(\s*\)',
        r'\bsession_start\s*\(\s*\)\s*;\s*\$_SESSION\[\w+\]\s*=\s*["\'][^"\']+["\']',
    ],
    "Header Injection": [
        r'(?i)\bheader\s*\(\s*["\']Location:.*\$_(GET|POST|REQUEST|COOKIE).*?["\']\s*\)',
        r'(?i)\bheader\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
    ],
    "Manual Deserialization": [
        r'(?i)\beval\s*\(\s*base64_decode\s*\(',
        r'(?i)\bunserialize\s*\(\s*base64_decode\s*\(',
    ],
    "Insecure Random": [
        r'(?i)\brand\s*\(',
        r'(?i)\bmt_rand\s*\(',
        r'(?i)\buniqid\s*\(',
        r'(?i)\b(Math\.random|Math\.floor)\s*\(',
    ],
    "Weak Hashing": [
        r'(?i)\b(md5|sha1|crc32)\s*\(',
    ],
    "Open Redirect": [
        r'(?i)\bheader\s*\(\s*["\']Location:\s*\'.*\$_(GET|POST|REQUEST|COOKIE).*?["\']\s*\)',
        r'(?i)\b(res\.redirect|window\.location)\s*\(\s*req\.(query|body|params)\[.*?\]',
    ],
    "Dynamic Class Instantiation": [
        r'(?i)\bnew\s+\$\w+',
    ],
    "Verbose Errors": [
        r'(?i)\btrigger_error\s*\(',
        r'(?i)\bdie\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
        r'(?i)\bexit\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*?\)',
    ],
    "Globals Misuse": [
        r'(?i)\bregister_globals\b',
        r'(?i)\b\$_GLOBALS\[.*?\]\s*=',
    ],
    "Hardcoded Secrets / Path": [
        r'(?i)["\'](C:\\|/var/www|/home/|/etc/passwd|\.pem|\.key|\.env)["\']',
        r'(?i)\b(res\.send|res\.json)\s*\(\s*process\.env',
        r'(?i)\b(readFileSync|readFile)\s*\(\s*[\'"](?:\.env|config\.js|settings\.json)[\'"]',
        r'(?i)\b(res\.setHeader|header)\s*\(\s*["\']Access-Control-Allow-Origin["\']\s*,\s*["\']\*["\'])',
        r'(?i)\b(file_get_contents|fopen)\s*\(.*["\'](\.env|config\.php|settings\.json|\.pem)["\']',

    ],
    "No verification": [
        r'(?i)\bjwt\.decode\s*\(\s*.*?\s*\)',
    ],
    "Regex Problem": [
        r'(?i)\([^\)]*?\.\*\)[+*?]'
    ],
        "PowerShell Commands": [
        r'(?i)\b(Invoke-Expression|iex|Set-ExecutionPolicy|Get-Command|Get-Process|Start-Process|Stop-Process|Get-Service|Set-Service|New-Item|Remove-Item|Get-Content|Set-Content)\s*(.*)',
        r'(?i)\b(Write-Output|Write-Host|Write-Verbose|Write-Debug|Write-Error)\s*(.*)',
        r'(?i)\b(Invoke-WebRequest|Invoke-RestMethod|curl|wget)\s*(.*)',
        r'(?i)\b(Get-Item|Set-Item|Copy-Item|Move-Item|Remove-Item|Test-Path|Clear-Content)\s*(.*)',
        r'(?i)\b(Enter-PSSession|Exit-PSSession|New-PSSession|Close-PSSession)\s*(.*)',
        r'(?i)\b(Expand-Archive|Compress-Archive)\s*(.*)',
    ],

}

def scan_php_files(paths):
    results = []
    total_files = 0
    processed_files = 0

    # First, count the total files to be scanned
    for path in paths:
        if not os.path.exists(path):
            print(f"[!] Path not found: {path}")
            continue
        if os.path.isfile(path) and path.endswith('.php'):
            total_files += 1
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                total_files += len([f for f in files if f.endswith('.php')])

    # Now, process the files
    for path in paths:
        if not os.path.exists(path):
            print(f"[!] Path not found: {path}")
            continue
        if os.path.isfile(path) and path.endswith('.php'):
            files_to_scan = [path]
        elif os.path.isdir(path):
            files_to_scan = []
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith('.php'):
                        files_to_scan.append(os.path.join(root, file))
        else:
            print(f"[!] Invalid path or not a .php file: {path}")
            continue

        for file_path in files_to_scan:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.readlines()
            except Exception as e:
                print(f"[!] Error reading file {file_path}: {e}")
                continue
            
            processed_files += 1
            # Show progress every time a file is processed
            progress = (processed_files / total_files) * 100
            print(f"\rReading files... {progress:.2f}% complete", end="")

            for line_number, line in enumerate(content, start=1):
                for vuln_type, regex_list in patterns.items():
                    for pattern in regex_list:
                        try:
                            if re.search(pattern, line):
                                results.append({
                                    "file": file_path,
                                    "line_number": line_number,
                                    "line": line.strip(),
                                    "vuln_type": vuln_type
                                })
                        except re.error:
                            pass
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PHP Vulnerability Scanner")
    parser.add_argument("paths", nargs='+', help="PHP file or directory paths to scan")
    parser.add_argument("-o", "--output", help="Output file to save results")
    args = parser.parse_args()

    vulnerabilities = scan_php_files(args.paths)

    if not vulnerabilities:
        msg = "[+] No vulnerabilities found."
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(msg)
            print(f"\n[+] Results saved to: {args.output}")
        else:
            print(msg)
    else:
        if args.output and args.output.lower().endswith('.json'):
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(vulnerabilities, f, indent=2)
            print(f"\n[+] Results saved to JSON: {args.output}")
        elif args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                for r in vulnerabilities:
                    f.write(f"{r['file']}:{r['line_number']} - {r['vuln_type']}\n")
                    f.write(f"   {r['line']}\n\n")
            print(f"\n[+] Results saved to: {args.output}")
        else:
            print("\n[!] Vulnerabilities detected:\n")
            for r in vulnerabilities:
                print(f"\033[91m{r['file']}:{r['line_number']} - {r['vuln_type']}\033[0m")
                print(f"   {r['line']}\n")