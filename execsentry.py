#!/usr/bin/env python3
"""
ExecSentry main CLI
"""

import argparse
import json
import sys
from core.utils import setup_logging, log
from core.http_scanner import HTTPScanner
from core.fs_scanner import FilesystemScanner
from core.config_scanner import ConfigScanner
from core.rules_engine import RulesEngine
from core.reporter import Reporter

VERSION = "1.0.0"

def parse_args():
    print("""
        ▓█████ ▒██   ██▒▓█████  ▄████▄    ██████ ▓█████  ███▄    █ ▄▄▄█████▓ ██▀███ ▓██   ██▓
        ▓█   ▀ ▒▒ █ █ ▒░▓█   ▀ ▒██▀ ▀█  ▒██    ▒ ▓█   ▀  ██ ▀█   █ ▓  ██▒ ▓▒▓██ ▒ ██▒▒██  ██▒
        ▒███   ░░  █   ░▒███   ▒▓█    ▄ ░ ▓██▄   ▒███   ▓██  ▀█ ██▒▒ ▓██░ ▒░▓██ ░▄█ ▒ ▒██ ██░
        ▒▓█  ▄  ░ █ █ ▒ ▒▓█  ▄ ▒▓▓▄ ▄██▒  ▒   ██▒▒▓█  ▄ ▓██▒  ▐▌██▒░ ▓██▓ ░ ▒██▀▀█▄   ░ ▐██▓░
        ░▒████▒▒██▒ ▒██▒░▒████▒▒ ▓███▀ ░▒██████▒▒░▒████▒▒██░   ▓██░  ▒██▒ ░ ░██▓ ▒██▒ ░ ██▒▓░
        ░░ ▒░ ░▒▒ ░ ░▓ ░░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒░   ▒ ▒   ▒ ░░   ░ ▒▓ ░▒▓░  ██▒▒▒ 
         ░ ░  ░░░   ░▒ ░ ░ ░  ░  ░  ▒   ░ ░▒  ░ ░ ░ ░  ░░ ░░   ░ ▒░    ░      ░▒ ░ ▒░▓██ ░▒░ 
           ░    ░    ░     ░   ░        ░  ░  ░     ░      ░   ░ ░   ░        ░░   ░ ▒ ▒ ░░  
           ░  ░ ░    ░     ░  ░░ ░            ░     ░  ░         ░             ░     ░ ░     
                               ░                                                     ░ ░             
            V-1.0.0
          """)
    parser = argparse.ArgumentParser(
        description="ExecSentry: Rule-based Arbitrary Binary Execution detection tool"
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    sub = parser.add_mutually_exclusive_group(required=True)
    sub.add_argument("--scan-http", nargs="+", help="Target base URL(s) to scan (e.g. https://example.com)")
    sub.add_argument("--scan-fs", nargs=1, help="Local filesystem path to scan")
    sub.add_argument("--scan-config", nargs=1, help="Path to configuration directory or file")
    sub.add_argument("--scan-all", nargs="+", help="Run HTTP + FS + Config scans (first arg is base URL)")

    parser.add_argument("--rules", default="rules/example_rules.json", help="Path to JSON rules file")
    parser.add_argument("--out-json", default="abe_report.json", help="Output JSON report file")
    parser.add_argument("--out-txt", default="abe_report.txt", help="Output TXT report file")
    parser.add_argument("--safe-testing", action="store_true", default=True,
                        help="Enable safe testing (no binary execution attempts). Default: True")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    return parser.parse_args()

def main():
    args = parse_args()
    if args.version:
        print("ExecSentry", VERSION)
        sys.exit(0)

    setup_logging(verbose=args.verbose)
    log.info("ExecSentry starting...")

    # Load rules
    rules_engine = RulesEngine.load_from_file(args.rules)
    reporter = Reporter()

    results = {
        "meta": {
            "tool": "ExecSentry",
            "version": VERSION,
            "safe_testing": bool(args.safe_testing)
        },
        "findings": []
    }

    if args.scan_http:
        scanner = HTTPScanner(rules_engine, timeout=args.timeout, safe_testing=args.safe_testing)
        for url in args.scan_http:
            log.info(f"Scanning HTTP target: {url}")
            findings = scanner.scan_site(url)
            results["findings"].extend(findings)

    if args.scan_fs:
        path = args.scan_fs[0]
        fs = FilesystemScanner(rules_engine)
        log.info(f"Scanning filesystem path: {path}")
        findings = fs.scan_path(path)
        results["findings"].extend(findings)

    if args.scan_config:
        path = args.scan_config[0]
        cs = ConfigScanner(rules_engine)
        log.info(f"Scanning config path: {path}")
        findings = cs.scan_config(path)
        results["findings"].extend(findings)

    if args.scan_all:
        # Expect first arg to be base URL, second optional is local path
        base_url = args.scan_all[0]
        fs_path = args.scan_all[1] if len(args.scan_all) > 1 else None
        scanner = HTTPScanner(rules_engine, timeout=args.timeout, safe_testing=args.safe_testing)
        findings = scanner.scan_site(base_url)
        results["findings"].extend(findings)
        if fs_path:
            fs = FilesystemScanner(rules_engine)
            findings = fs.scan_path(fs_path)
            results["findings"].extend(findings)
        # additionally scan default config directories
        cs = ConfigScanner(rules_engine)
        findings = cs.scan_config(".")
        results["findings"].extend(findings)

    # Finalize report
    reporter.write_json(args.out_json, results)
    reporter.write_txt(args.out_txt, results)
    log.info(f"Reports written: {args.out_json}, {args.out_txt}")
    print(f"Scan complete. Findings: {len(results['findings'])}. Reports saved.")

if __name__ == "__main__":
    main()
