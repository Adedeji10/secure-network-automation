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
    return '\n'.join(lines)

def get_exit_code(report):
    return 1 if report['pipeline_decision'] == 'BLOCK' else 0
