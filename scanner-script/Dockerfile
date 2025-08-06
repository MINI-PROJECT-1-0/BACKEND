
# Dockerfile for Penetration Testing Toolkit
FROM kalilinux/kali-rolling

# This will install dependencies
RUN apt-get update && \
    apt-get install -y \
    nmap \
    nikto \
    zaproxy \
    sqlmap \
    dirb \
    gobuster \
    metasploit-framework \
    python3 \
    python3-pip \
    git \
    whois \
    dnsenum \
    && apt-get clean

# This will install Python packages
RUN pip3 install requests bs4

# This create directory structure
RUN mkdir -p /scripts /reports /wordlists

# This add common wordlist
RUN cp /usr/share/wordlists/dirb/common.txt /wordlists/

# This create all scripts in /scripts directory
RUN mkdir -p /scripts && \
    cat > /scripts/common.sh << 'EOF'
#!/bin/bash

# common.sh - Common functions and variables for vulnerability scanning scripts

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to validate URL
validate_url() {
    local url=$1
    if [[ ! $url =~ ^https?:// ]]; then
        echo -e "${RED}Error: Invalid URL format. Please include http:// or https://${NC}" >&2
        exit 1
    fi
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check for required tools
check_requirements() {
    local tools=("$@")
    local missing=()

    for tool in "${tools[@]}"; do
        if ! command_exists "$tool"; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Error: Missing required tools: ${missing[*]}${NC}" >&2
        exit 1
    fi
}

# Function to parse cookies from string to JSON
parse_cookies() {
    local cookie_str=$1
    if [ -z "$cookie_str" ]; then
        echo "{}"
        return
    fi

    local json="{"
    IFS=';' read -ra COOKIES <<< "$cookie_str"
    for cookie in "${COOKIES[@]}"; do
        IFS='=' read -r key value <<< "$(echo "$cookie" | xargs)"
        json+="\"$key\":\"$value\","
    done
    json="${json%,}}"

    echo "$json"
}
EOF

RUN cat > /scripts/recon.sh << 'EOF'
#!/bin/bash

# recon.sh -  Reconnaissance script

# Include common functions and arguments
source /scripts/common.sh

# Parse arguments
while getopts ":u:o:H:C:x:D:A:" opt; do
    case $opt in
        u) TARGET_URL="$OPTARG"
        ;;
        o) OUTPUT_DIR="$OPTARG"
        ;;
        H) HEADERS_FILE="$OPTARG"
        ;;
        C) COOKIES="$OPTARG"
        ;;
        x) PROXY="$OPTARG"
        ;;
        D) DELAY="$OPTARG"
        ;;
        A) USER_AGENT="$OPTARG"
        ;;
        \?) echo "Invalid option -$OPTARG" >&2; exit 1
        ;;
    esac
done

validate_url "$TARGET_URL"
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting reconnaissance on $TARGET_URL"

# Build curl options
CURL_OPTS="-s -A \"$USER_AGENT\""
if [ -n "$PROXY" ]; then
    CURL_OPTS="$CURL_OPTS --proxy $PROXY"
fi
if [ -n "$COOKIES" ]; then
    CURL_OPTS="$CURL_OPTS -b \"$COOKIES\""
fi
if [ -n "$HEADERS_FILE" ]; then
    CURL_OPTS="$CURL_OPTS -H @\"$HEADERS_FILE\""
fi

# 1. WHOIS lookup with delay
echo "[*] Performing WHOIS lookup"
whois $(echo $TARGET_URL | cut -d'/' -f3) > "$OUTPUT_DIR/whois.txt"
sleep $DELAY

# 2. DNS enumeration with delay
echo "[*] Performing DNS enumeration"
dnsenum $(echo $TARGET_URL | cut -d'/' -f3) > "$OUTPUT_DIR/dnsenum.txt"
sleep $DELAY

# 3. Nmap scan with custom options
echo "[*] Running Nmap scan"
NMAP_OPTS="-sV -T4 -A"
if [ -n "$PROXY" ]; then
    NMAP_OPTS="$NMAP_OPTS --proxies $PROXY"
fi
nmap $NMAP_OPTS -oA "$OUTPUT_DIR/nmap_scan" $(echo $TARGET_URL | cut -d'/' -f3)

echo "[+] Reconnaissance complete. Results saved to $OUTPUT_DIR"
EOF

RUN cat > /scripts/vuln_scan.sh << 'EOF'
#!/bin/bash
# vuln_scan.sh - Vulnerability scanning

source /scripts/common.sh

# Parse arguments
while getopts ":u:o:H:C:x:D:A:" opt; do
    case $opt in
        u) TARGET_URL="$OPTARG"
        ;;
        o) OUTPUT_DIR="$OPTARG"
        ;;
        H) HEADERS_FILE="$OPTARG"
        ;;
        C) COOKIES="$OPTARG"
        ;;
        x) PROXY="$OPTARG"
        ;;
        D) DELAY="$OPTARG"
        ;;
        A) USER_AGENT="$OPTARG"
        ;;
        \?) echo "Invalid option -$OPTARG" >&2; exit 1
        ;;
    esac
done

validate_url "$TARGET_URL"
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting vulnerability scan on $TARGET_URL"

# 1. Nikto scan with custom options
echo "[*] Running Nikto scan"
NIKTO_OPTS="-h $TARGET_URL -output $OUTPUT_DIR/nikto_scan.html -Format htm"
if [ -n "$USER_AGENT" ]; then
    NIKTO_OPTS="$NIKTO_OPTS -useragent \"$USER_AGENT\""
fi
if [ -n "$COOKIES" ]; then
    NIKTO_OPTS="$NIKTO_OPTS -Cookies \"$COOKIES\""
fi
if [ -n "$PROXY" ]; then
    NIKTO_OPTS="$NIKTO_OPTS -useproxy $PROXY"
fi
if [ "$DELAY" != "0" ]; then
    NIKTO_OPTS="$NIKTO_OPTS -delay $DELAY"
fi

eval nikto $NIKTO_OPTS

# 2. OWASP ZAP baseline scan with custom options
echo "[*] Running OWASP ZAP baseline scan"
ZAP_OPTS="-t $TARGET_URL -r $OUTPUT_DIR/zap_report.html"
if [ -n "$PROXY" ]; then
    ZAP_OPTS="$ZAP_OPTS -z \"-config proxy.address=$(echo $PROXY | cut -d':' -f2 | sed 's|//||')\""
fi
if [ -n "$COOKIES" ]; then
    ZAP_OPTS="$ZAP_OPTS -z \"-config network.cookie=$COOKIES\""
fi
if [ "$DELAY" != "0" ]; then
    ZAP_OPTS="$ZAP_OPTS -m $DELAY"
fi

zap-baseline.py $ZAP_OPTS

echo "[+] Vulnerability scan complete. Results saved to $OUTPUT_DIR"
EOF

RUN cat > /scripts/dir_brute.sh << 'EOF'
#!/bin/bash

# dir_brute.sh - Directory brute-forcing script

source /scripts/common.sh

# Parse arguments
while getopts ":u:o:w:H:C:x:D:A:" opt; do
    case $opt in
        u) TARGET_URL="$OPTARG"
        ;;
        o) OUTPUT_DIR="$OPTARG"
        ;;
        w) WORDLIST="$OPTARG"
        ;;
        H) HEADERS_FILE="$OPTARG"
        ;;
        C) COOKIES="$OPTARG"
        ;;
        x) PROXY="$OPTARG"
        ;;
        D) DELAY="$OPTARG"
        ;;
        A) USER_AGENT="$OPTARG"
        ;;
        \?) echo "Invalid option -$OPTARG" >&2; exit 1
        ;;
    esac
done

validate_url "$TARGET_URL"
mkdir -p "$OUTPUT_DIR"
WORDLIST=${WORDLIST:-/wordlists/common.txt}

echo "[*] Starting directory brute-forcing on $TARGET_URL"

# 1. Gobuster scan with custom options
echo "[*] Running Gobuster scan"
GOBUSTER_OPTS="dir -u $TARGET_URL -w $WORDLIST -o $OUTPUT_DIR/gobuster_scan.txt"
if [ -n "$USER_AGENT" ]; then
    GOBUSTER_OPTS="$GOBUSTER_OPTS -a \"$USER_AGENT\""
fi
if [ -n "$COOKIES" ]; then
    GOBUSTER_OPTS="$GOBUSTER_OPTS -c \"$COOKIES\""
fi
if [ -n "$PROXY" ]; then
    GOBUSTER_OPTS="$GOBUSTER_OPTS -p \"$PROXY\""
fi
if [ "$DELAY" != "0" ]; then
    GOBUSTER_OPTS="$GOBUSTER_OPTS -d $DELAY"
fi

eval gobuster $GOBUSTER_OPTS

# 2. Dirb scan with custom options
echo "[*] Running Dirb scan"
DIRB_OPTS="$TARGET_URL $WORDLIST -o $OUTPUT_DIR/dirb_scan.txt"
if [ -n "$USER_AGENT" ]; then
    DIRB_OPTS="$DIRB_OPTS -a \"$USER_AGENT\""
fi
if [ -n "$COOKIES" ]; then
    DIRB_OPTS="$DIRB_OPTS -c \"$COOKIES\""
fi
if [ -n "$PROXY" ]; then
    DIRB_OPTS="$DIRB_OPTS -p \"$PROXY\""
fi
if [ "$DELAY" != "0" ]; then
    DIRB_OPTS="$DIRB_OPTS -z $DELAY"
fi

eval dirb $DIRB_OPTS

echo "[+] Directory brute-forcing complete. Results saved to $OUTPUT_DIR"
EOF

RUN cat > /scripts/sql_test.sh << 'EOF'
#!/bin/bash

# sql_test.sh - SQL injection testing script

source /scripts/common.sh

# Parse arguments
while getopts ":u:o:H:C:x:D:A:" opt; do
    case $opt in
        u) TARGET_URL="$OPTARG"
        ;;
        o) OUTPUT_DIR="$OPTARG"
        ;;
        H) HEADERS_FILE="$OPTARG"
        ;;
        C) COOKIES="$OPTARG"
        ;;
        x) PROXY="$OPTARG"
        ;;
        D) DELAY="$OPTARG"
        ;;
        A) USER_AGENT="$OPTARG"
        ;;
        \?) echo "Invalid option -$OPTARG" >&2; exit 1
        ;;
    esac
done

validate_url "$TARGET_URL"
mkdir -p "$OUTPUT_DIR/sqlmap"
echo "[*] Starting SQL injection testing on $TARGET_URL"

# Run SQLmap with custom options
echo "[*] Running SQLmap"
SQLMAP_OPTS="-u $TARGET_URL --batch --output-dir=$OUTPUT_DIR/sqlmap --crawl=2"
if [ -n "$USER_AGENT" ]; then
    SQLMAP_OPTS="$SQLMAP_OPTS --user-agent=\"$USER_AGENT\""
fi
if [ -n "$COOKIES" ]; then
    SQLMAP_OPTS="$SQLMAP_OPTS --cookie=\"$COOKIES\""
fi
if [ -n "$PROXY" ]; then
    SQLMAP_OPTS="$SQLMAP_OPTS --proxy=$PROXY"
fi
if [ "$DELAY" != "0" ]; then
    SQLMAP_OPTS="$SQLMAP_OPTS --delay=$DELAY"
fi
if [ -n "$HEADERS_FILE" ]; then
    SQLMAP_OPTS="$SQLMAP_OPTS --headers=@\"$HEADERS_FILE\""
fi

eval sqlmap $SQLMAP_OPTS

echo "[+] SQL injection testing complete. Results saved to $OUTPUT_DIR/sqlmap"
EOF

RUN cat > /scripts/xss_test.py << 'EOF'
#!/usr/bin/env python3

# xss_test.py - XSS vulnerability checker(this is in python)

import requests
from bs4 import BeautifulSoup
import sys
import urllib.parse
import json
import time
import argparse

def load_headers(headers_file):
    try:
        with open(headers_file, 'r') as f:
            return json.load(f)
    except:
        return None

def test_xss(url, headers=None, cookies=None, proxy=None, delay=0, user_agent=None):
    test_payload = "<script>alert('XSS')</script>"

    # Set up session
    session = requests.Session()

    # Configure session
    if headers:
        session.headers.update(headers)
    if cookies:
        session.cookies.update({c.split('=')[0]: c.split('=')[1] for c in cookies.split('; ')})
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    if user_agent:
        session.headers.update({'User-Agent': user_agent})

    try:
        # Test in URL parameters
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param in params:
            test_url = url.replace(param + "=" + params[param][0], param + "=" + urllib.parse.quote(test_payload))
            response = session.get(test_url)
            if test_payload in response.text:
                print(f"[!] Possible XSS vulnerability found in parameter: {param}")
            time.sleep(delay)

        # Test in form fields if any
        response = session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            form_details = {}
            action = form.attrs.get('action', '').lower()
            method = form.attrs.get('method', 'get').lower()

            inputs = []
            for input_tag in form.find_all('input'):
                input_name = input_tag.attrs.get('name')
                input_type = input_tag.attrs.get('type', 'text')
                inputs.append({'type': input_type, 'name': input_name})

            for input in inputs:
                if input['type'] == 'text' or input['type'] == 'search':
                    data = {input['name']: test_payload}
                    if method == 'post':
                        res = session.post(url + action, data=data)
                    else:
                        res = session.get(url + action, params=data)

                    if test_payload in res.text:
                        print(f"[!] Possible XSS vulnerability found in form field: {input['name']}")
                    time.sleep(delay)

    except Exception as e:
        print(f"[!] Error: {e}")
        if name == "main":
            parser = argparse.ArgumentParser(description='XSS Vulnerability Tester')
            parser.add_argument('-u', '--url', required=True, help='Target URL')
            parser.add_argument('-H', '--headers', help='Headers JSON file')
            parser.add_argument('-C', '--cookies', help='Cookies string')
            parser.add_argument('-x', '--proxy', help='Proxy URL')
            parser.add_argument('-D', '--delay', type=float, default=0, help='Delay between requests')
            parser.add_argument('-A', '--user-agent', help='Custom User-Agent string')

            args = parser.parse_args()

            headers = load_headers(args.headers) if args.headers else None
            cookies = args.cookies if args.cookies else None
            proxy = args.proxy if args.proxy else None
            delay = args.delay if args.delay else 0
            user_agent = args.user_agent if args.user_agent else None

            print(f"[*] Testing XSS vulnerabilities on {args.url}")
            test_xss(args.url, headers, cookies, proxy, delay, user_agent)
            print("[*] XSS testing complete")
EOF

RUN cat > /scripts/pentest.sh << 'EOF'
#!/bin/bash

# pentest.sh - Master penetration testing script

source /scripts/common.sh

# Parse arguments
while getopts ":u:o:d:w:H:C:x:D:s:r:A:h" opt; do
        case $opt in
            u) TARGET_URL="$OPTARG"
                ;;
                o) OUTPUT_DIR="$OPTARG"
                ;;
                d) DEPTH="$OPTARG"
                ;;
                w) WORDLIST="$OPTARG"
                ;;
                H) HEADERS_FILE="$OPTARG"
                ;;
                C) COOKIES="$OPTARG"
                ;;
                x) PROXY="$OPTARG"
                ;;
                D) DELAY="$OPTARG"
                ;;
                s) SKIP_TESTS="$OPTARG"
                ;;
                r) RUN_ONLY="$OPTARG"
                ;;
                A) USER_AGENT="$OPTARG"
                ;;
                h) echo "Usage: $0 -u <target_url> [options]"; exit 0
                ;;
                \?) echo "Invalid option -$OPTARG" >&2; exit 1
                ;;
            esac
        done

        validate_url "$TARGET_URL"
        mkdir -p "$OUTPUT_DIR"
        WORDLIST=${WORDLIST:-/wordlists/common.txt}

        echo "[*] Starting comprehensive penetration test on $TARGET_URL"

        # Determine which tests to run
        declare -A TESTS=(
            ["recon"]=1
            ["vuln"]=1
            ["dir"]=1
            ["sql"]=1
            ["xss"]=1
        )

        # Process skip and run-only options
        if [ -n "$RUN_ONLY" ]; then
            # Reset all tests
            for key in "${!TESTS[@]}"; do
                TESTS["$key"]=0
            done
            # Enable only specified tests
            IFS=',' read -ra RUN_TESTS <<< "$RUN_ONLY"
            for test in "${RUN_TESTS[@]}"; do
                if [ -n "${TESTS[$test]}" ]; then
                    TESTS["$test"]=1
                fi
            done
        elif [ -n "$SKIP_TESTS" ]; then
            IFS=',' read -ra SKIP_TESTS <<< "$SKIP_TESTS"
            for test in "${SKIP_TESTS[@]}"; do
                if [ -n "${TESTS[$test]}" ]; then
                    TESTS["$test"]=0
                fi
            done
        fi

        # Run selected tests
        if [ "${TESTS[recon]}" -eq 1 ]; then
            echo "[*] Running reconnaissance tests"
            /scripts/recon.sh -u "$TARGET_URL" -o "$OUTPUT_DIR/recon" ${HEADERS_FILE:+-H "$HEADERS_FILE"} ${COOKIES:+-C "$COOKIES"} ${PROXY:+-x "$PROXY"} -D "$DELAY" ${USER_AGENT:+-A "$USER_AGENT"}
        fi

        if [ "${TESTS[vuln]}" -eq 1 ]; then
            echo "[*] Running vulnerability scans"
            /scripts/vuln_scan.sh -u "$TARGET_URL" -o "$OUTPUT_DIR/vuln_scan" ${HEADERS_FILE:+-H "$HEADERS_FILE"} ${COOKIES:+-C "$COOKIES"} ${PROXY:+-x "$PROXY"} -D "$DELAY" ${USER_AGENT:+-A "$USER_AGENT"}
        fi

        if [ "${TESTS[dir]}" -eq 1 ]; then
            echo "[*] Running directory brute-forcing"
            /scripts/dir_brute.sh -u "$TARGET_URL" -o "$OUTPUT_DIR/dir_brute" -w "$WORDLIST" ${HEADERS_FILE:+-H "$HEADERS_FILE"} ${COOKIES:+-C "$COOKIES"} ${PROXY:+-x "$PROXY"} -D "$DELAY" ${USER_AGENT:+-A "$USER_AGENT"}
        fi

        if [ "${TESTS[sql]}" -eq 1 ]; then
            echo "[*] Running SQL injection tests"
            /scripts/sql_test.sh -u "$TARGET_URL" -o "$OUTPUT_DIR/sql_test" ${HEADERS_FILE:+-H "$HEADERS_FILE"} ${COOKIES:+-C "$COOKIES"} ${PROXY:+-x "$PROXY"} -D "$DELAY" ${USER_AGENT:+-A "$USER_AGENT"}
        fi
        if [ "${TESTS[xss]}" -eq 1 ]; then
            echo "[*] Running XSS tests"
            python3 /scripts/xss_test.py -u "$TARGET_URL" ${HEADERS_FILE:+-H "$HEADERS_FILE"} ${COOKIES:+-C "$COOKIES"} ${PROXY:+-x "$PROXY"} -D "$DELAY" ${USER_AGENT:+-A "$USER_AGENT"} > "$OUTPUT_DIR/xss_test.txt"
        fi

        # This generate final report for the test
        echo "[*] Generating final report"
        echo "Penetration Test Report for $TARGET_URL" > "$OUTPUT_DIR/final_report.txt"
        echo "======================================" >> "$OUTPUT_DIR/final_report.txt"
        echo "" >> "$OUTPUT_DIR/final_report.txt"
        echo "Test Options:" >> "$OUTPUT_DIR/final_report.txt"
        echo "------------" >> "$OUTPUT_DIR/final_report.txt"
        echo "Target URL: $TARGET_URL" >> "$OUTPUT_DIR/final_report.txt"
        echo "User Agent: $USER_AGENT" >> "$OUTPUT_DIR/final_report.txt"
        if [ -n "$PROXY" ]; then echo "Proxy: $PROXY" >> "$OUTPUT_DIR/final_report.txt"; fi
        if [ -n "$COOKIES" ]; then echo "Cookies: $COOKIES" >> "$OUTPUT_DIR/final_report.txt"; fi
        if [ -n "$HEADERS_FILE" ]; then echo "Custom Headers: From $HEADERS_FILE" >> "$OUTPUT_DIR/final_report.txt"; fi
        echo "Request Delay: $DELAY seconds" >> "$OUTPUT_DIR/final_report.txt"
        echo "" >> "$OUTPUT_DIR/final_report.txt"

        # Include test results
        for test in "${!TESTS[@]}"; do
            if [ "${TESTS[$test]}" -eq 1 ]; then
                echo "${test^^} Findings:" >> "$OUTPUT_DIR/final_report.txt"
                echo "----------------" >> "$OUTPUT_DIR/final_report.txt"
                case $test in
                    recon) cat "$OUTPUT_DIR/recon/nmap_scan.nmap" >> "$OUTPUT_DIR/final_report.txt"
                    ;;
                    vuln) grep -i "vulnerable" "$OUTPUT_DIR/vuln_scan/nikto_scan.html" >> "$OUTPUT_DIR/final_report.txt"
                    ;;
                    dir) cat "$OUTPUT_DIR/dir_brute/gobuster_scan.txt" >> "$OUTPUT_DIR/final_report.txt"
                    ;;
                    sql) cat "$OUTPUT_DIR/sql_test/output" >> "$OUTPUT_DIR/final_report.txt"
                    ;;
                    xss) cat "$OUTPUT_DIR/xss_test.txt" >> "$OUTPUT_DIR/final_report.txt"
                    ;;
                esac
                echo "" >> "$OUTPUT_DIR/final_report.txt"
            fi
        done

        echo "[+] Penetration test complete. Final report saved to $OUTPUT_DIR/final_report.txt"
EOF

        # To make scripts executable
RUN chmod +x /scripts/*.sh /scripts/*.py

        # Set working directory
WORKDIR /scripts

        # Entry point
ENTRYPOINT ["/scripts/pentest.sh"]
CMD ["-h"]
