"""
Rules engine: loads JSON signature rules and exposes checks
Rules are pure, deterministic patterns / heuristics
"""
import json
import re
from typing import List, Dict, Callable
from core.utils import SUSPICIOUS_CMD_RE

class Rule:
    def __init__(self, rule_id: str, title: str, severity: str, description: str, kind: str, pattern: str=None):
        self.id = rule_id
        self.title = title
        self.severity = severity
        self.description = description
        self.kind = kind  # 'http', 'fs', 'config', 'code'
        self.pattern = pattern
        self._re = re.compile(pattern, re.IGNORECASE) if pattern else None

    def match_text(self, text: str):
        if not self._re:
            return False
        return bool(self._re.search(text))

class RulesEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    @classmethod
    def load_from_file(cls, path: str):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = []
        for r in data.get("rules", []):
            rules.append(Rule(
                r.get("id"),
                r.get("title"),
                r.get("severity","medium"),
                r.get("description",""),
                r.get("kind","generic"),
                r.get("pattern")
            ))
        return cls(rules)

    def match_code(self, code_text: str):
        findings = []
        for rule in self.rules:
            if rule.kind in ("fs","code") and rule.match_text(code_text):
                findings.append(rule)
        return findings

    def match_config(self, config_text: str):
        findings = []
        for rule in self.rules:
            if rule.kind == "config" and rule.match_text(config_text):
                findings.append(rule)
        return findings

    def match_http_headers(self, headers: dict):
        findings = []
        header_text = "\n".join(f"{k}:{v}" for k,v in headers.items())
        for rule in self.rules:
            if rule.kind == "http" and rule.match_text(header_text):
                findings.append(rule)
        return findings
