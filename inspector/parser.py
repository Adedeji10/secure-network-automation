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
    return re.sub(r'\s+', ' ', line.strip().lower())

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
                match = re.match(r'^hostname\s+(\S+)', line.strip())
                if match:
                    metadata['hostname'] = match.group(1)
                    break
    except Exception:
        pass
    return metadata
