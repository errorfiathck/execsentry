"""
Configuration scanner: parse common config files and look for unsafe exec/load entries.
Parsers for systemd unit files, crontabs, YAML, JSON, and dotenv-style files.
"""

import os
from core.utils import log, sanitize_path
import re
import json
import yaml

class ConfigScanner:
    def __init__(self, rules_engine):
        self.rules = rules_engine

    def _scan_text_for_config_rules(self, text, path):
        findings = []
        matched = self.rules.match_config(text)
        for r in matched:
            findings.append({
                "path": path,
                "type": "config-rule-match",
                "rule_id": r.id,
                "rule_title": r.title,
                "description": r.description
            })
        return findings

    def _parse_crontab(self, text, path):
        findings = []
        lines = text.splitlines()
        for ln in lines:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            # look for scripts in /tmp or upload dirs
            if re.search(r"(?:/tmp/|/var/tmp/|/uploads/|/home/.*?/uploads/)", ln):
                findings.append({
                    "path": path,
                    "type": "crontab-sus-upload-exec",
                    "line": ln,
                    "message": "Crontab references script in commonly writable dirs (tmp/uploads)"
                })
        return findings

    def scan_config(self, path):
        base = sanitize_path(path)
        findings = []
        if os.path.isfile(base):
            files = [base]
        else:
            files = []
            for root, dirs, fnames in os.walk(base):
                for f in fnames:
                    files.append(os.path.join(root, f))
        for fpath in files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except Exception as e:
                continue
            # generic config rules
            findings.extend(self._scan_text_for_config_rules(text, fpath))
            # crontab heuristics
            if os.path.basename(fpath) in ("crontab", "crontabs", "cron", "crontab.txt") or "cron" in fpath.lower():
                findings.extend(self._parse_crontab(text, fpath))
            # systemd unit file heuristic: ExecStart lines
            if fpath.endswith(".service") or "systemd" in fpath.lower():
                for ln in text.splitlines():
                    if "ExecStart" in ln:
                        if re.search(r"(?:/tmp/|/var/tmp|/uploads|/home/.*?/uploads)", ln, flags=re.IGNORECASE):
                            findings.append({
                                "path": fpath,
                                "type":"systemd-exec-suspicious",
                                "line": ln.strip(),
                                "message": "systemd unit executes a script from a writable/untrusted directory"
                            })
            # JSON/YAML inspection for plugin directories or dynamic loaders
            if fpath.endswith((".yml",".yaml",".json")):
                try:
                    j = None
                    if fpath.endswith(".json"):
                        j = json.loads(text)
                    else:
                        j = yaml.safe_load(text)
                    # shallow check: keys like plugin_dir, upload_dir, modules
                    if isinstance(j, dict):
                        for k,v in j.items():
                            if isinstance(k, str) and "plugin" in k.lower() or "upload" in k.lower():
                                findings.append({
                                    "path": fpath,
                                    "type":"config-key",
                                    "key": k,
                                    "value": v,
                                    "message":"Config references plugin/upload directory; review for untrusted loading"
                                })
                except Exception:
                    # ignore parse errors
                    pass
        return findings
