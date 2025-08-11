# Optimized Kali-based Penetration Testing Toolkit
FROM kalilinux/kali-rolling

LABEL maintainer="Williams Adusei (swiftwilliams@gmail.com)" \
      version="2025.08" \
      description="Optimized Kali-based Penetration Testing Toolkit"

# 1) Install dependencies and Python libraries
RUN set -euo pipefail && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      nmap nikto sqlmap dirb gobuster \
      python3 python3-pip whois dnsrecon \
      wget dos2unix && \
    pip3 install --break-system-packages --no-cache-dir requests beautifulsoup4 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 2) Create folders for scripts, reports, and wordlists
RUN mkdir -p /scripts /reports /wordlists

# 3) Download wordlists with failure checks
RUN wget -q -O /wordlists/common.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt || exit 1 && \
    wget -q -O /wordlists/directory-list-2.3-medium.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt || exit 1 && \
    wget -q -O /wordlists/xss-payloads.txt \
      https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt || exit 1

# 4) Install and fix line endings on all embedded scripts

## common.sh (Fixed color codes)
RUN cat << 'EOF' > /scripts/common.sh
#!/usr/bin/env bash
set -euo pipefail

die() {
  [ -t 1 ] && echo -e "\033[0;31m[ERROR] $*\033[0m" >&2 \
           || echo "[ERROR] $*" >&2
  exit 1
}

info() {
  [ -t 1 ] && echo -e "\033[0;32m[INFO] $*\033[0m" \
           || echo "[INFO] $*"
}

warn() {
  [ -t 1 ] && echo -e "\033[1;33m[WARN] $*\033[0m" \
           || echo "[WARN] $*"
}

check_requirements() {
  local miss=()
  for cmd; do
    command -v "$cmd" >/dev/null 2>&1 || miss+=("$cmd")
  done
  (( ${#miss[@]} )) && die "Missing tools: ${miss[*]}"
}

validate_url() {
  [[ "$1" =~ ^https?://.+ ]] || die "Invalid URL '$1'. Must start with http:// or https://"
}

show_help() {
  cat << HELP
Usage: $(basename "$0") -u <target_url> -o <output_dir> [-w <wordlist>] [-D <delay>] [-h]

  -u  Target URL (must include protocol)
  -o  Output directory
  -w  Wordlist (default: /wordlists/common.txt)
  -D  Delay between requests (seconds)
  -h  Show this help
HELP
  exit 0
}
EOF

## recon.sh (Fixed color codes and Nmap output)
RUN cat << 'EOF' > /scripts/recon.sh
#!/usr/bin/env bash
set -euo pipefail
source /scripts/common.sh

DELAY=0
while getopts "u:o:D:h" opt; do
  case $opt in
    u) TARGET_URL="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    D) DELAY="$OPTARG" ;;
    h) show_help ;;
    *) show_help ;;
  esac
done

[[ -z "${TARGET_URL:-}" ]] && die "Target URL required (-u)"
[[ -z "${OUTPUT_DIR:-}" ]] && die "Output directory required (-o)"

validate_url "$TARGET_URL"
check_requirements whois dnsrecon nmap

mkdir -p "$OUTPUT_DIR"
info "Starting reconnaissance on $TARGET_URL"

DOMAIN=$(echo "$TARGET_URL" | awk -F[/:] '{print $4}')

whois "$DOMAIN" > "$OUTPUT_DIR/whois.txt"
dnsrecon -d "$DOMAIN" > "$OUTPUT_DIR/dnsenum.txt"
nmap -sV -T4 -A -oN "$OUTPUT_DIR/nmap.txt" "$DOMAIN"

info "Reconnaissance complete"
EOF

## vuln_scan.sh (Fixed output format)
RUN cat << 'EOF' > /scripts/vuln_scan.sh
#!/usr/bin/env bash
set -euo pipefail
source /scripts/common.sh

while getopts "u:o:h" opt; do
  case $opt in
    u) TARGET_URL="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    h) show_help ;;
    *) show_help ;;
  esac
done

[[ -z "${TARGET_URL:-}" ]] && die "Target URL required (-u)"
[[ -z "${OUTPUT_DIR:-}" ]] && die "Output directory required (-o)"

validate_url "$TARGET_URL"
check_requirements nikto

mkdir -p "$OUTPUT_DIR"
info "Starting vulnerability scan on $TARGET_URL"

nikto -h "$TARGET_URL" -output "$OUTPUT_DIR/nikto.txt" -Format txt

info "Vulnerability scan complete"
EOF

## dir_brute.sh (Fixed color codes)
RUN cat << 'EOF' > /scripts/dir_brute.sh
#!/usr/bin/env bash
set -euo pipefail
source /scripts/common.sh

WORDLIST="/wordlists/common.txt"
while getopts "u:o:w:h" opt; do
  case $opt in
    u) TARGET_URL="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    h) show_help ;;
    *) show_help ;;
  esac
done

[[ -z "${TARGET_URL:-}" ]] && die "Target URL required (-u)"
[[ -z "${OUTPUT_DIR:-}" ]] && die "Output directory required (-o)"

validate_url "$TARGET_URL"
check_requirements gobuster dirb

mkdir -p "$OUTPUT_DIR"
info "Starting directory brute-forcing on $TARGET_URL"

gobuster dir -u "$TARGET_URL" -w "$WORDLIST" -o "$OUTPUT_DIR/gobuster.txt"
dirb "$TARGET_URL" "$WORDLIST" -o "$OUTPUT_DIR/dirb.txt"

info "Directory brute complete"
EOF

## sql_test.sh (Fixed output handling)
RUN cat << 'EOF' > /scripts/sql_test.sh
#!/usr/bin/env bash
set -euo pipefail
source /scripts/common.sh

while getopts "u:o:h" opt; do
  case $opt in
    u) TARGET_URL="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    h) show_help ;;
    *) show_help ;;
  esac
done

[[ -z "${TARGET_URL:-}" ]] && die "Target URL required (-u)"
[[ -z "${OUTPUT_DIR:-}" ]] && die "Output directory required (-o)"

validate_url "$TARGET_URL"
check_requirements sqlmap

mkdir -p "$OUTPUT_DIR"
info "Starting SQL injection testing on $TARGET_URL"

sqlmap -u "$TARGET_URL" --batch --output-dir="$OUTPUT_DIR/sqlmap" > "$OUTPUT_DIR/sql_results.txt"

info "SQL injection test complete"
EOF

## xss_test.py (Fixed BeautifulSoup import)
RUN cat << 'EOF' > /scripts/xss_test.py
#!/usr/bin/env python3
import argparse, requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

PAYLOAD = '<script>alert(1)</script>'

def parse_args():
    p = argparse.ArgumentParser(description="Basic XSS tester")
    p.add_argument('-u','--url', required=True)
    p.add_argument('-o','--output', required=True)
    return p.parse_args()

def reflect_test(base, params):
    parsed = urlparse(base)
    found = []
    for k,_ in params:
        q = dict(params); q[k] = PAYLOAD
        test = urlunparse(parsed._replace(query=urlencode(q)))
        try:
            r = requests.get(test, timeout=10)
            if PAYLOAD in r.text:
                found.append(f"Reflected XSS in parameter: {k}")
                found.append(f"URL: {test}")
        except Exception as e:
            print(f"Error testing {k}: {str(e)}")
    return found

def main():
    args = parse_args()
    qs = parse_qsl(urlparse(args.url).query)
    results = reflect_test(args.url, qs)
    with open(args.output, 'w') as f:
        f.write("XSS Test Results\n")
        f.write("="*40 + "\n")
        if results:
            f.write("\n".join(results))
            f.write("\n\nVulnerable URLs found: " + str(len(results)//2)
        else:
            f.write("No reflected XSS vulnerabilities found")
    print(f"[+] XSS test results saved to {args.output}")

if __name__ == '__main__':
    main()
EOF

## pentest.sh (Fixed report generation and Python call)
RUN cat << 'EOF' > /scripts/pentest.sh
#!/usr/bin/env bash
set -euo pipefail
source /scripts/common.sh

WORDLIST="/wordlists/common.txt"
DELAY=0

while getopts "u:o:w:D:h" opt; do
  case $opt in
    u) TARGET_URL="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    D) DELAY="$OPTARG" ;;
    h) show_help ;;
    *) show_help ;;
  esac
done

[[ -z "${TARGET_URL:-}" ]] && die "Target URL required (-u)"
[[ -z "${OUTPUT_DIR:-}" ]] && die "Output directory required (-o)"

validate_url "$TARGET_URL"
mkdir -p "$OUTPUT_DIR"

info "Starting comprehensive penetration test on $TARGET_URL"

# Initialize report
REPORT="$OUTPUT_DIR/final_report.txt"
echo "Penetration Test Report" > "$REPORT"
echo "=======================" >> "$REPORT"
echo "Target URL: $TARGET_URL" >> "$REPORT"
echo "Start Time: $(date)" >> "$REPORT"
echo "" >> "$REPORT"

# Run tests and capture output
run_test() {
    echo -e "\n=== $1 ===" >> "$REPORT"
    shift
    if "$@" >> "$REPORT" 2>&1; then
        info "$1 completed successfully"
    else
        warn "$1 encountered issues"
    fi
}

run_test "Reconnaissance" /scripts/recon.sh -u "$TARGET_URL" -o "$OUTPUT_DIR/recon" -D "$DELAY"
run_test "Vulnerability Scanning" /scripts/vuln_scan.sh -u "$TARGET_URL" -o "$OUTPUT_DIR/vuln"
run_test "Directory Brute-forcing" /scripts/dir_brute.sh -u "$TARGET_URL" -o "$OUTPUT_DIR/dir_brute" -w "$WORDLIST"
run_test "SQL Injection Testing" /scripts/sql_test.sh -u "$TARGET_URL" -o "$OUTPUT_DIR/sql"
run_test "XSS Testing" /usr/bin/python3 /scripts/xss_test.py -u "$TARGET_URL" -o "$OUTPUT_DIR/xss_results.txt"

# Finalize report
echo -e "\nTest Summary" >> "$REPORT"
echo "============" >> "$REPORT"
find "$OUTPUT_DIR" -name '*.txt' -exec grep -EH 'Found|Vulnerable|Reflected' {} \; >> "$REPORT" 2>/dev/null || true

echo "" >> "$REPORT"
echo "End Time: $(date)" >> "$REPORT"
info "Penetration test completed"
info "Full report saved to: $REPORT"
EOF

# 5) Set permissions and normalize line endings
RUN chmod +x /scripts/*.sh /scripts/*.py && \
    dos2unix /scripts/*

# 6) Create robust entrypoint wrapper
RUN printf '#!/bin/sh\n\nexec /bin/bash /scripts/pentest.sh "$@"\n' > /entrypoint.sh \
    && chmod +x /entrypoint.sh \
    && dos2unix /entrypoint.sh

WORKDIR /scripts
VOLUME [ "/reports" ]

ENTRYPOINT [ "/bin/sh", "/entrypoint.sh" ]
CMD [ "-h" ]
