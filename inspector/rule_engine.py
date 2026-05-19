import re
from parser import parse_config, is_comment_line, normalise_line

SECURITY_RULES = [
    # CRITICAL (8)
    {"id":"CIS-001","description":"Telnet service is enabled",
     "severity":"critical","pattern":r"^service\s+telnet",
     "remediation":"Remove telnet: no service telnet"},
    {"id":"CIS-002","description":"VTY line permits Telnet transport",
     "severity":"critical","pattern":r"transport\s+input\s+(telnet|all)",
     "remediation":"Set: transport input ssh"},
    {"id":"CIS-003","description":"HTTP server is enabled",
     "severity":"critical","pattern":r"^ip\s+http\s+server$",
     "remediation":"Disable: no ip http server"},
    {"id":"CIS-004","description":"Default SNMP community public configured",
     "severity":"critical","pattern":r"snmp-server\s+community\s+public",
     "remediation":"Remove: no snmp-server community public"},
    {"id":"CIS-005","description":"Default SNMP community private configured",
     "severity":"critical","pattern":r"snmp-server\s+community\s+private",
     "remediation":"Remove: no snmp-server community private"},
    {"id":"CIS-006","description":"VTY line has no login authentication",
     "severity":"critical","pattern":r"^\s*no\s+login",
     "remediation":"Enable: login local on all VTY lines"},
    {"id":"CIS-007","description":"SSH version 1 is configured",
     "severity":"critical","pattern":r"ip\s+ssh\s+version\s+1",
     "remediation":"Upgrade: ip ssh version 2"},
    {"id":"CIS-008","description":"CDP is enabled exposing device information",
     "severity":"critical","pattern":r"^cdp\s+run",
     "remediation":"Disable: no cdp run"},
    # HIGH - Encryption (10)
    {"id":"NIST-001","description":"SSH version 2 is not configured",
     "severity":"high","check_missing":True,
     "required_pattern":r"ip\s+ssh\s+version\s+2",
     "remediation":"Configure: ip ssh version 2"},
    {"id":"NIST-002","description":"Password encryption service is disabled",
     "severity":"high","pattern":r"no\s+service\s+password-encryption",
     "remediation":"Enable: service password-encryption"},
    {"id":"NIST-003","description":"Enable password used instead of enable secret",
     "severity":"high","pattern":r"^enable\s+password\s+",
     "remediation":"Replace with: enable secret <password>"},
    {"id":"NIST-004","description":"Plaintext username password configured",
     "severity":"high","pattern":r"username\s+\S+\s+password\s+",
     "remediation":"Use: username <name> secret <password>"},
    {"id":"NIST-005","description":"SNMP community with RW access configured",
     "severity":"high","pattern":r"snmp-server\s+community\s+\S+\s+RW",
     "remediation":"Change RW to RO and restrict with ACL"},
    {"id":"NIST-006","description":"VTY exec-timeout not configured",
     "severity":"high","check_missing":True,
     "required_pattern":r"exec-timeout",
     "remediation":"Set: exec-timeout 5 0"},
    {"id":"NIST-007","description":"HTTP secure server enabled",
     "severity":"high","pattern":r"^ip\s+http\s+secure-server",
     "remediation":"Disable: no ip http secure-server"},
    {"id":"NIST-008","description":"Finger service is enabled",
     "severity":"high","pattern":r"^service\s+finger",
     "remediation":"Disable: no service finger"},
    {"id":"NIST-009","description":"TCP small servers enabled",
     "severity":"high","pattern":r"service\s+tcp-small-servers",
     "remediation":"Disable: no service tcp-small-servers"},
    {"id":"NIST-010","description":"UDP small servers enabled",
     "severity":"high","pattern":r"service\s+udp-small-servers",
     "remediation":"Disable: no service udp-small-servers"},
    # HIGH - Access Control (6)
    {"id":"CIS-ACL-001","description":"VTY lines accessible without ACL restriction",
     "severity":"high","check_missing":True,
     "required_pattern":r"access-class",
     "remediation":"Apply: access-class MGMT-ACCESS in"},
    {"id":"CIS-ACL-002","description":"Console line not configured",
     "severity":"high","check_missing":True,
     "required_pattern":r"line\s+con\s+0",
     "remediation":"Configure: line con 0 / login local"},
    {"id":"CIS-ACL-003","description":"Transport input set to all on VTY",
     "severity":"high","pattern":r"transport\s+input\s+all",
     "remediation":"Restrict: transport input ssh"},
    {"id":"CIS-ACL-004","description":"No username configured for local auth",
     "severity":"high","check_missing":True,
     "required_pattern":r"^username\s+",
     "remediation":"Add: username admin privilege 15 secret <pass>"},
    {"id":"CIS-ACL-005","description":"Weak SNMP community string detected",
     "severity":"high",
     "pattern":r"snmp-server\s+community\s+(admin|cisco|network|manager|monitor)",
     "remediation":"Use strong unique community string with ACL"},
    {"id":"CIS-ACL-006","description":"VTY line 0 15 open - too broad",
     "severity":"high","pattern":r"line\s+vty\s+0\s+15",
     "remediation":"Restrict: line vty 0 4 with access-class"},
    # MEDIUM - Logging (9)
    {"id":"LOG-001","description":"No syslog server configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"logging\s+host",
     "remediation":"Configure: logging host <syslog-ip>"},
    {"id":"LOG-002","description":"Logging explicitly disabled",
     "severity":"medium","pattern":r"no\s+logging\s+host",
     "remediation":"Enable: logging host <syslog-ip>"},
    {"id":"LOG-003","description":"Logging buffered not configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"logging\s+buffered",
     "remediation":"Configure: logging buffered 16384"},
    {"id":"LOG-004","description":"No login banner MOTD configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"banner\s+motd",
     "remediation":"Add: banner motd ^ Authorized Access Only ^"},
    {"id":"LOG-005","description":"Banner explicitly removed",
     "severity":"medium","pattern":r"no\s+banner\s+motd",
     "remediation":"Restore: banner motd ^ Authorized Access Only ^"},
    {"id":"LOG-006","description":"Logging trap level not set",
     "severity":"medium","check_missing":True,
     "required_pattern":r"logging\s+trap",
     "remediation":"Set: logging trap informational"},
    {"id":"LOG-007","description":"SNMP not configured for monitoring",
     "severity":"medium","check_missing":True,
     "required_pattern":r"snmp-server\s+community",
     "remediation":"Configure SNMP with restricted community string"},
    {"id":"LOG-008","description":"ACL deny entries missing log keyword",
     "severity":"medium","pattern":r"deny\s+any(?!.*log)",
     "remediation":"Add log: deny any log"},
    {"id":"LOG-009","description":"SSH authentication retries not configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"ip\s+ssh\s+authentication-retries",
     "remediation":"Set: ip ssh authentication-retries 3"},
    # MEDIUM - NTP (4)
    {"id":"NTP-001","description":"No NTP server configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"ntp\s+server",
     "remediation":"Configure: ntp server <ntp-ip>"},
    {"id":"NTP-002","description":"NTP explicitly disabled",
     "severity":"medium","pattern":r"no\s+ntp\s+server",
     "remediation":"Enable: ntp server <ntp-ip>"},
    {"id":"NTP-003","description":"NTP update-calendar not configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"ntp\s+update-calendar",
     "remediation":"Add: ntp update-calendar"},
    {"id":"NTP-004","description":"SSH timeout not configured",
     "severity":"medium","check_missing":True,
     "required_pattern":r"ip\s+ssh\s+time-out",
     "remediation":"Set: ip ssh time-out 60"},
    # LOW - Documentation (5)
    {"id":"DOC-001","description":"Hostname does not follow naming convention",
     "severity":"low","pattern":r"^hostname\s+(?!R\d|SW\d|FW\d)[A-Za-z]",
     "remediation":"Use R1-R9, SW1-SW9, FW1-FW9 naming convention"},
    {"id":"DOC-002","description":"No interface description configured",
     "severity":"low","check_missing":True,
     "required_pattern":r"^\s+description\s+",
     "remediation":"Add descriptions to all interfaces"},
    {"id":"DOC-003","description":"No device type comment header",
     "severity":"low","check_missing":True,
     "required_pattern":r"!\s+[Tt]ype:",
     "remediation":"Add header: ! Type: Router/Switch/Firewall"},
    {"id":"DOC-004","description":"No location comment in config",
     "severity":"low","check_missing":True,
     "required_pattern":r"!\s+[Ll]ocation:",
     "remediation":"Add: ! Location: <location>"},
    {"id":"DOC-005","description":"No generation date comment",
     "severity":"low","check_missing":True,
     "required_pattern":r"!\s+[Gg]enerated:",
     "remediation":"Add: ! Generated: YYYY-MM-DD"},
]

def apply_rules(parsed_lines, rules=None):
    if rules is None:
        rules = SECURITY_RULES
    violations = []
    full_config = '\n'.join(line for _, line in parsed_lines)
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
            # Skip negation lines for positive-match rules
            # e.g. "no snmp-server community public" is compliant
            if normalised.strip().startswith('no '):
                # Only skip for specific community/service rules
                skip_rules = ['CIS-004','CIS-005','CIS-003',
                               'NIST-007','NIST-008','NIST-009','NIST-010']
                if rule.get('id') in skip_rules:
                    continue
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
