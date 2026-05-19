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
    print('Found ' + str(len(config_files)) + ' configuration files\n')
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
    print('\n' + sep)
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
        print('\n  PIPELINE DECISION: BLOCK')
        print('  Ansible deployment will NOT proceed.\n')
    else:
        print('\n  PIPELINE DECISION: PASS')
        print('  Ansible deployment may proceed.\n')
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
