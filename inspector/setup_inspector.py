import os

files = {}

# ─────────────────────────────────────────────
files['parser.py'] = """\
import os
import re

def parse_config(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError("Config file not found: " + file_path)
    file_size = os.path.getsize(file_path)
    if file_size > 10 * 1024 * 1024:
        raise ValueError("File exceeds 10MB limit")
    parsed_lines = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip()
            if not line.strip():
                continue
            parsed_lines.append((line_number, line))
    return parsed_lines

def is_comment_line(line):
    return line.strip().startswith('!')

def normalise_line(line):
    return re.sub(r'\\s+', ' ', line.strip().lower())

def get_file_metadata(file_path):
    metadata = {
        'file_path': file_path,
        'file_name': os.path.basename(file_path),
        'file_size_bytes': os.path.getsize(file_path),
        'hostname': 'unknown',
        'device_type': 'unknown'
    }
    if 'router' in file_path.lower():
        metadata['device_type'] = 'router'
    elif 'switch' in file_path.lower():
        metadata['device_type'] = 'switch'
    elif 'firewall' in file_path.lower():
        metadata['device_type'] = 'firewall'
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = re.match(r'^hostname\\s+(\\S+)', line.strip())
                if match:
                    metadata['hostname'] = match.group(1)
                    break
    except Exception:
        pass
    return metadata
"""

# ─────────────────────────────────────────────
files['rule_engine.py'] = """\
import re
from parser import parse_config, is_comment_line, normalise_line

SECURITY_RULES = [
    # CRITICAL (8)
    {"id":"CIS-001","description":"Telnet service is enabled",
     "severity":"critical","pattern":r"^service\\s+telnet",
     "remediation":"Remove telnet: no service telnet"},
    {"id":"CIS-002","description":"VTY line permits Telnet transport",
     "severity":"critical","pattern":r"transport\\s+input\\s+(telnet|all)",
     "remediation":"Set: transport input ssh"},
    {"id":"CIS-003","description":"HTTP server is enabled",
     "severity":"critical","pattern":r"^ip\\s+http\\s+server$",
     "remediation":"Disable: no ip http server"},
    {"id":"CIS-004","description":"Default SNMP community public configured",
     "severity":"critical","pattern":r"snmp-server\\s+community\\s+public",
     "remediation":"Remove: no snmp-server community public"},
    {"id":"CIS-005","description":"Default SNMP community private configured",
     "severity":"critical","pattern":r"snmp-server\\s+community\\s+private",
     "remediation":"Remove: no snmp-server community private"},
    {"id":"CIS-006","description":"VTY line has no login authentication",
     "severity":"critical","pattern":r"^\\s*no\\s+login",
     "remediation":"Enable: login local on all VTY lines"},
    {"id":"CIS-007","description":"SSH version 1 is configured",
     "severity":"critical","pattern":r"ip\\s+ssh\\s+version\\s+1",
     "remediation":"Upgrade: ip ssh version 2"},
    {"id":"CIS-008","description":"CDP is enabled exposing device information",
     "severity":"critical","pattern":r"^cdp\\s+run",
     "remediation":"Disable: no cdp run"},
    # HIGH - Encryption (10)
    {"id":"NIST-001","description":"SSH version 2 is not configured",
     "severity":"high","check_missing":True,
     "required_pattern":r"ip\\s+ssh\\s+version\\s+2",
     "remediation":"Configure: ip ssh version 2"},
    {"id":"NIST-002","description":"Password encryption service is disabled",
     "severity":"high","pattern":r"no\\s+service\\s+password-encryption",
     "remediation":"Enable: service password-encryption"},
    {"id":"NIST-003","description":"Enable password used instead of enable secret",
     "severity":"high","pattern":r"^enable\\s+password\\s+",
     "remediation":"Replace with: enable secret <password>"},
    {"id":"NIST-004","description":"Plaintext username password configured",
     "severity":"high","pattern":r"username\\s+\\S+\\s+password\\s+",
     "remediation":"Use: username <name> secret <password>"},
    {"id":"NIST-005","description":"SNMP community with RW access configured",
     "severity":"high","pattern":r"snmp-server\\s+community\\s+\\S+\\s+RW",
     "remediation":"Change RW to RO and restrict with ACL"},
    {"id":"NIST-006","description":"VTY exec-timeout not configured",
     "severity":"high","check_missing":True,
     "required_pattern":r"exec-timeout",
     "remediation":"Set: exec-timeout 5 0"},
    {"id":"NIST-007","description":"HTTP secure server enabled",
     "severity":"high","pattern":r"^ip\\s+http\\s+secure-server",
     "remediation":"Disable: no ip http secure-server"},
    {"id":"NIST-008","description":"Finger service is enabled",
     "severity":"high","pattern":r"^service\\s+finger",
     "remediation":"Disable: no service finger"},
    {"id":"NIST-009","description":"TCP small servers enabled",
     "severity":"high","pattern":r"service\\s+tcp-small-servers",
     "remediation":"Disable: no service tcp-small-servers"},
    {"id":"NIST-010","description":"UDP small servers enabled",
     "severity":"high","pattern":r"service\\s+udp-small-servers",
     "remediation":"Disable: no service udp-small-servers"},
    # HIGH - Access Control (6)
    {"id":"CIS-ACL-001","description":"VTY lines accessible without ACL restriction",
     "severity":"high","check_missing":True,
     "required_pattern":r"access-class",
     "remediation":"Apply: access-class MGMT-ACCESS in"},
    {"id":"CIS-ACL-002","description":"Console line not configured",
     "severity":"high","check_missing":True,
     "required_pattern":r"line\\s+con\\s+0",
     "remediation":"Configure: line con 0 / login local"},
    {"id":"CIS-ACL-003","description":"Transport input set to all on VTY",
     "severity":"high","pattern":r"transport\\s+input\\s+all",
     "remediation":"Restrict: transport input ssh"},
    {"id":"CIS-ACL-004","description":"No username configured for local auth",
     "severity":"high","check_missing":True,
     "required_pattern":r"^username\\s+",
     "remediation":"Add: username admin privilege 15 secret <pass>"},
    {"id":"CIS-ACL-005","description":"Weak SNMP community string detected",
     "severity":"high",
     "pattern":r"snmp-server\\s+community\\s+(admin|cisco|network|manager|monitor)",
     "remediation":"Use strong unique community string with ACL"},
    {"id":"CIS-ACL-006","description":"VTY line 0 15 open - too broad",
     "severity":"high","pattern":r"line\\s+vty\\s+0\\s+15",
     "remediation":"Restrict: line vty 0 4 with access-class"},
    # MEDIUM - Logging (9)
    {"id":"LOG-001","description":"No syslog server configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"logging\\s+host",
     "remediation":"Configure: logging host <syslog-ip>"},
    {"id":"LOG-002","description":"Logging explicitly disabled",
     "severity":"medium","pattern":r"no\\s+logging\\s+host",
     "remediation":"Enable: logging host <syslog-ip>"},
    {"id":"LOG-003","description":"Logging buffered not configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"logging\\s+buffered",
     "remediation":"Configure: logging buffered 16384"},
    {"id":"LOG-004","description":"No login banner MOTD configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"banner\\s+motd",
     "remediation":"Add: banner motd ^ Authorized Access Only ^"},
    {"id":"LOG-005","description":"Banner explicitly removed",
     "severity":"medium","pattern":r"no\\s+banner\\s+motd",
     "remediation":"Restore: banner motd ^ Authorized Access Only ^"},
    {"id":"LOG-006","description":"Logging trap level not set",
     "severity":"medium","check_missing":True,
     "required_pattern":r"logging\\s+trap",
     "remediation":"Set: logging trap informational"},
    {"id":"LOG-007","description":"SNMP not configured for monitoring",
     "severity":"medium","check_missing":True,
     "required_pattern":r"snmp-server\\s+community",
     "remediation":"Configure SNMP with restricted community string"},
    {"id":"LOG-008","description":"ACL deny entries missing log keyword",
     "severity":"medium","pattern":r"deny\\s+any(?!.*log)",
     "remediation":"Add log: deny any log"},
    {"id":"LOG-009","description":"SSH authentication retries not configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"ip\\s+ssh\\s+authentication-retries",
     "remediation":"Set: ip ssh authentication-retries 3"},
    # MEDIUM - NTP (4)
    {"id":"NTP-001","description":"No NTP server configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"ntp\\s+server",
     "remediation":"Configure: ntp server <ntp-ip>"},
    {"id":"NTP-002","description":"NTP explicitly disabled",
     "severity":"medium","pattern":r"no\\s+ntp\\s+server",
     "remediation":"Enable: ntp server <ntp-ip>"},
    {"id":"NTP-003","description":"NTP update-calendar not configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"ntp\\s+update-calendar",
     "remediation":"Add: ntp update-calendar"},
    {"id":"NTP-004","description":"SSH timeout not configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"ip\\s+ssh\\s+time-out",
     "remediation":"Set: ip ssh time-out 60"},
    # LOW - Documentation (5)
    {"id":"DOC-001","description":"Hostname does not follow naming convention",
     "severity":"low","pattern":r"^hostname\\s+(?!R\\d|SW\\d|FW\\d)[A-Za-z]",
     "remediation":"Use R1-R9, SW1-SW9, FW1-FW9 naming convention"},
    {"id":"DOC-002","description":"No interface description configured",
     "severity":"low","check_missing":True,
     "required_pattern":r"^\\s+description\\s+",
     "remediation":"Add descriptions to all interfaces"},
    {"id":"DOC-003","description":"No device type comment header",
     "severity":"low","check_missing":True,
     "required_pattern":r"!\\s+[Tt]ype:",
     "remediation":"Add header: ! Type: Router/Switch/Firewall"},
    {"id":"DOC-004","description":"No location comment in config",
     "severity":"low","check_missing":True,
     "required_pattern":r"!\\s+[Ll]ocation:",
     "remediation":"Add: ! Location: <location>"},
    {"id":"DOC-005","description":"No generation date comment",
     "severity":"low","check_missing":True,
     "required_pattern":r"!\\s+[Gg]enerated:",
     "remediation":"Add: ! Generated: YYYY-MM-DD"},
]

def apply_rules(parsed_lines, rules=None):
    if rules is None:
        rules = SECURITY_RULES
    violations = []
    full_config = '\\n'.join(line for _, line in parsed_lines)
    for rule in rules:
        if rule.get('check_missing'):
            required = rule.get('required_pattern', '')
            if required and not re.search(
                required, full_config, re.IGNORECASE | re.MULTILINE
            ):
                violations.append({
                    'rule_id': rule['id'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'line_number': 0,
                    'line_content': '(required configuration absent)',
                    'remediation': rule['remediation']
                })
            continue
        for line_number, line in parsed_lines:
            if is_comment_line(line):
                continue
            normalised = normalise_line(line)
            if re.search(rule['pattern'], normalised, re.IGNORECASE):
                violations.append({
                    'rule_id': rule['id'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'line_number': line_number,
                    'line_content': line.strip(),
                    'remediation': rule['remediation']
                })
    return violations
"""

# ─────────────────────────────────────────────
files['reporter.py'] = """\
import json
import datetime

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

def generate_report(file_path, violations, metadata):
    critical = [v for v in violations if v['severity'] == 'critical']
    high     = [v for v in violations if v['severity'] == 'high']
    medium   = [v for v in violations if v['severity'] == 'medium']
    low      = [v for v in violations if v['severity'] == 'low']
    if critical or high:
        decision = 'BLOCK'
    elif medium or low:
        decision = 'PASS_WITH_WARNINGS'
    else:
        decision = 'PASS'
    return {
        'audit_timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'inspector_version': '1.0.0',
        'file_audited': file_path,
        'device_hostname': metadata.get('hostname', 'unknown'),
        'device_type': metadata.get('device_type', 'unknown'),
        'pipeline_decision': decision,
        'summary': {
            'total_violations': len(violations),
            'critical': len(critical),
            'high': len(high),
            'medium': len(medium),
            'low': len(low)
        },
        'violations': sorted(
            violations,
            key=lambda v: SEVERITY_ORDER.get(v['severity'], 99)
        )
    }

def to_json(report, indent=2):
    return json.dumps(report, indent=indent)

def to_text(report):
    lines = []
    sep = '=' * 65
    lines.append(sep)
    lines.append('  INSPECTOR AUDIT REPORT')
    lines.append(sep)
    lines.append('  File     : ' + report['file_audited'])
    lines.append('  Hostname : ' + report['device_hostname'])
    lines.append('  Type     : ' + report['device_type'])
    lines.append('  Time     : ' + report['audit_timestamp'])
    lines.append(sep)
    decision = report['pipeline_decision']
    if decision == 'BLOCK':
        lines.append('  DECISION : *** BLOCK - DEPLOYMENT PREVENTED ***')
    elif decision == 'PASS_WITH_WARNINGS':
        lines.append('  DECISION : PASS WITH WARNINGS (advisory only)')
    else:
        lines.append('  DECISION : PASS - Configuration is compliant')
    s = report['summary']
    lines.append(sep)
    lines.append('  VIOLATIONS: Total=' + str(s['total_violations']) +
                 '  Critical=' + str(s['critical']) +
                 '  High=' + str(s['high']) +
                 '  Medium=' + str(s['medium']) +
                 '  Low=' + str(s['low']))
    lines.append(sep)
    if report['violations']:
        lines.append('  DETAILS')
        lines.append('')
        for i, v in enumerate(report['violations'], 1):
            lines.append('  [' + str(i) + '] [' + v['severity'].upper() +
                         '] ' + v['rule_id'] + ' - ' + v['description'])
            if v['line_number'] > 0:
                lines.append('      Line ' + str(v['line_number']) +
                             ': ' + v['line_content'])
            else:
                lines.append('      ' + v['line_content'])
            lines.append('      FIX: ' + v['remediation'])
            lines.append('')
    else:
        lines.append('  No violations detected.')
    lines.append(sep)
    return '\\n'.join(lines)

def get_exit_code(report):
    return 1 if report['pipeline_decision'] == 'BLOCK' else 0
"""

# ─────────────────────────────────────────────
files['audit.py'] = """\
import sys
import os
import time
import argparse
from parser import parse_config, get_file_metadata
from rule_engine import apply_rules
from reporter import generate_report, to_text, to_json, get_exit_code

def audit_file(file_path, verbose=True):
    start_time = time.time()
    parsed_lines = parse_config(file_path)
    metadata = get_file_metadata(file_path)
    violations = apply_rules(parsed_lines)
    report = generate_report(file_path, violations, metadata)
    elapsed = round(time.time() - start_time, 4)
    report['audit_duration_seconds'] = elapsed
    if verbose:
        print(to_text(report))
    return report, get_exit_code(report), elapsed

def audit_directory(dir_path):
    config_files = []
    for root, dirs, files in os.walk(dir_path):
        for f in files:
            if f.endswith('.txt'):
                config_files.append(os.path.join(root, f))
    config_files.sort()
    if not config_files:
        print('No .txt config files found in ' + dir_path)
        return 0
    print('Found ' + str(len(config_files)) + ' configuration files\\n')
    overall_exit = 0
    results = []
    for cf in config_files:
        report, exit_code, elapsed = audit_file(cf, verbose=True)
        results.append({
            'file': cf,
            'decision': report['pipeline_decision'],
            'critical': report['summary']['critical'],
            'high': report['summary']['high'],
            'medium': report['summary']['medium'],
            'low': report['summary']['low'],
            'duration': elapsed
        })
        if exit_code == 1:
            overall_exit = 1
    sep = '=' * 65
    print('\\n' + sep)
    print('  BATCH AUDIT SUMMARY')
    print(sep)
    passed = blocked = warned = 0
    for r in results:
        fname = os.path.basename(r['file'])[:34]
        dec = r['decision']
        if dec == 'BLOCK':
            blocked += 1
        elif dec == 'PASS_WITH_WARNINGS':
            warned += 1
        else:
            passed += 1
        print('  ' + fname.ljust(35) + dec.ljust(24) +
              str(r['critical']).rjust(2) +
              str(r['high']).rjust(3) +
              str(r['medium']).rjust(3) +
              str(r['low']).rjust(3))
    print(sep)
    print('  PASSED         : ' + str(passed))
    print('  PASS+WARNINGS  : ' + str(warned))
    print('  BLOCKED        : ' + str(blocked))
    print('  TOTAL          : ' + str(len(results)))
    print(sep)
    if overall_exit == 1:
        print('\\n  PIPELINE DECISION: BLOCK')
        print('  Ansible deployment will NOT proceed.\\n')
    else:
        print('\\n  PIPELINE DECISION: PASS')
        print('  Ansible deployment may proceed.\\n')
    return overall_exit

def main():
    parser = argparse.ArgumentParser(
        description='Inspector - Network Config Security Auditor'
    )
    parser.add_argument('target', help='Config file or directory')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    if os.path.isdir(args.target):
        exit_code = audit_directory(args.target)
    elif os.path.isfile(args.target):
        report, exit_code, _ = audit_file(args.target,
                                           verbose=not args.json)
        if args.json:
            print(to_json(report))
    else:
        print('Error: ' + args.target + ' not found')
        exit_code = 2
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
"""

# Write all files
for filename, content in files.items():
    with open(filename, 'w') as f:
        f.write(content)
    print('Written: ' + filename)

print('\\nAll Inspector files created successfully.')
