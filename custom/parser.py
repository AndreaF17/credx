#!/usr/bin/env python3
import csv
import argparse
import sys

from custom.credential_extractor import extract_credentials_from_line


_CSV_INJECTION_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def csv_safe(value):
    """Neutralize spreadsheet formula injection in a CSV cell."""
    text = '' if value is None else str(value)
    return ("'" + text) if text[:1] in _CSV_INJECTION_PREFIXES else text


def anonymize_password(password):
    """Anonymize the middle of a password with asterisks.
    Keeps first and last character visible, replaces the rest with *."""
    if len(password) <= 2:
        return password[0] + '*' * (len(password) - 1)
    return password[0] + '*' * (len(password) - 2) + password[-1]


def parse_line_candidates(line):
    """Parse all credentials in a line and return list of (target_url, user, password)."""
    candidates = extract_credentials_from_line(line, mode='aggressive')
    return [(item['url'], item['identity'], item['password']) for item in candidates]


def main():
    parser = argparse.ArgumentParser(description='Parse credential output to anonymized CSV')
    parser.add_argument('-i', '--input', type=str, help='Input txt file with credentials', required=True)
    parser.add_argument('-o', '--output', type=str, help='Output CSV file', default=None)
    args = parser.parse_args()

    if not args.output:
        args.output = args.input.rsplit('.', 1)[0] + '.csv'

    parsed = []
    seen = set()
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            for line in f:
                results = parse_line_candidates(line)
                if results:
                    for target, user, password in results:
                        dedup_key = f"{user.lower()}:{password}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        parsed.append((target, user, anonymize_password(password)))
                elif line.strip():
                    print(f"[WARNING] Skipped unparseable line: {line.strip()}", file=sys.stderr)
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow(['TARGET', 'User', 'Password'])
            for target, user, password in parsed:
                writer.writerow([csv_safe(target), csv_safe(user), csv_safe(password)])
    except Exception as e:
        print(f"[ERROR] Failed to write CSV: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Parsed {len(parsed)} credentials -> {args.output}")


if __name__ == '__main__':
    main()