"""
Filesystem scanner: scans local code and directories to find suspicious code patterns,
world-writable upload/plugin directories, and other local misconfigurations.
This is deterministic static analysis using regex rules.
"""
import os
import stat
from core.utils import log, SUSPICIOUS_CMD_RE, sanitize_path
from typing import List

class FilesystemScanner:
    def __init__(self, rules_engine):
        self.rules = rules_engine

    def _is_world_writable(self, path):
        try:
            mode = os.stat(path).st_mode
            return bool(mode & (stat.S_IWOTH))
        except Exception:
            return False

    def _scan_file_for_patterns(self, path):
        findings = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            # check suspicious code uses
            if SUSPICIOUS_CMD_RE.search(text):
                findings.append({
                    "file": path,
                    "type": "suspicious-code-pattern",
                    "message": "Detected possible usage of subprocess/os.system/exec/etc.",
                    "matched": SUSPICIOUS_CMD_RE.findall(text)[:5]
                })
            # Rule engine code matches
            matched_rules = self.rules.match_code(text)
            for r in matched_rules:
                findings.append({
                    "file": path,
                    "type": "code-rule-match",
                    "rule_id": r.id,
                    "rule_title": r.title,
                    "description": r.description
                })
        except Exception as e:
            log.debug(f"Failed to scan file {path}: {e}")
        return findings

    def scan_path(self, root_path: str):
        root = sanitize_path(root_path)
        findings = []
        if not os.path.exists(root):
            log.error(f"Path not found: {root}")
            return findings
        for dirpath, dirnames, filenames in os.walk(root):
            # check directory writability
            if self._is_world_writable(dirpath):
                findings.append({
                    "path": dirpath,
                    "type": "world-writable-dir",
                    "message": "Directory is world-writable and may accept untrusted uploads"
                })
            # suspicious plugin dirs (heuristic)
            basename = os.path.basename(dirpath).lower()
            if basename in ("plugins","uploads","ext","extensions","modules","addons"):
                findings.append({
                    "path": dirpath,
                    "type": "suspicious-dir-name",
                    "message": f"Directory named '{basename}' found; review for untrusted file loading"
                })
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                # check file extension of binaries
                if fname.lower().endswith((".so",".dll",".exe")):
                    findings.append({
                        "path": full,
                        "type": "native-binary-file",
                        "message": "Native binary file found in repository tree; check for dynamic loading from untrusted dirs"
                    })
                # scan code files
                if fname.lower().endswith((".py",".php",".js",".sh",".pl",".rb")):
                    findings.extend(self._scan_file_for_patterns(full))
        return findings
