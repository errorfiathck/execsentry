"""
HTTP scanner: finds upload forms, probes safe file uploads using non-executable stubs,
and applies deterministic heuristics to detect potential execution or processing.
"""

import requests
from bs4 import BeautifulSoup
from core.utils import make_marker, log
from core.rules_engine import Rule
from typing import List, Dict
import urllib.parse
import mimetypes
import os
import time

class HTTPScanner:
    def __init__(self, rules_engine, timeout=10, safe_testing=True):
        self.rules = rules_engine
        self.timeout = timeout
        self.safe_testing = safe_testing
        self.session = requests.Session()
        self.session.headers.update({"User-Agent":"ExecSentry/1.0"})

    def _get_page(self, url: str):
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return r
        except Exception as e:
            log.debug(f"GET {url} failed: {e}")
            return None

    def discover_upload_forms(self, base_url: str, crawl_depth=1) -> List[Dict]:
        """
        Crawl base_url root and discover HTML forms with input type=file
        Returns list of dicts: {url, form_action, enctype, method, fields}
        """
        to_visit = [base_url]
        discovered = []
        visited = set()
        for _ in range(crawl_depth):
            new = []
            for u in to_visit:
                if u in visited: continue
                visited.add(u)
                r = self._get_page(u)
                if not r or r.status_code != 200:
                    continue
                soup = BeautifulSoup(r.text, "html.parser")
                # forms
                for form in soup.find_all("form"):
                    inputs = form.find_all("input")
                    has_file = any(i.get("type","").lower()=="file" for i in inputs)
                    if has_file:
                        action = form.get("action") or u
                        action = urllib.parse.urljoin(u, action)
                        enctype = form.get("enctype","")
                        method = form.get("method","post").lower()
                        fields = {i.get("name"): i.get("type","text") for i in inputs if i.get("name")}
                        discovered.append({
                            "page": u,
                            "action": action,
                            "enctype": enctype,
                            "method": method,
                            "fields": fields
                        })
                # links to follow
                for a in soup.find_all("a", href=True):
                    href = urllib.parse.urljoin(u, a["href"])
                    if href.startswith(base_url):
                        new.append(href)
            to_visit = new
        return discovered

    def safe_upload_probe(self, action_url: str, file_field_name: str="file",
                           filename="probe.txt", content="probe", extra_fields=None):
        """
        Uploads a harmless text probe file under filename. Does NOT upload binary/executable content.
        Returns response and any accessible path (via Location header or predictable path heuristics).
        """
        files = {
            file_field_name: (filename, content, "text/plain")
        }
        data = extra_fields or {}
        try:
            r = self.session.post(action_url, files=files, data=data, timeout=self.timeout, allow_redirects=False)
            return r
        except Exception as e:
            log.debug(f"POST {action_url} failed: {e}")
            return None

    def guess_upload_url_from_response(self, base_url: str, response):
        """
        Heuristic: if response has Location header, or JSON body with url/file path, return candidate URL
        """
        if not response:
            return None
        loc = response.headers.get("Location")
        if loc:
            # make absolute
            return urllib.parse.urljoin(base_url, loc)
        ct = response.headers.get("Content-Type","")
        try:
            if "application/json" in ct:
                j = response.json()
                # common keys
                for k in ("url","file","path","location"):
                    if k in j and isinstance(j[k], str):
                        return urllib.parse.urljoin(base_url, j[k])
        except Exception:
            pass
        # Else try to search body for likely paths
        text = response.text if hasattr(response, "text") else ""
        # simple regex for /uploads/... or /files/...
        import re
        m = re.search(r'(\/[^\s"\']*(?:uploads|files|uploads\/images|tmp)[^\s"\']*)', text)
        if m:
            return urllib.parse.urljoin(base_url, m.group(1))
        return None

    def analyze_upload_response(self, response, probe_marker):
        """
        Heuristics to decide if uploaded file might be executed/processed:
        - HTTP 500 or server error after upload may indicate processing
        - Presence of specific headers (X-Powered-By, Server) that match known processors
        - JSON response includes "processed", "executed", "task", "job"
        - If accessing the uploaded file URL returned in Location responds with Content-Type that is not text/plain (e.g., text/html executed)
        Note: This is heuristic only and deterministic — it gathers evidence; severity scored by rules engine.
        """
        findings = []
        if not response:
            return findings
        if response.status_code >= 500:
            findings.append({
                "type":"server-error-during-upload",
                "message":"Server returned 5xx after upload — may indicate processing/execution",
                "status_code": response.status_code
            })
        # JSON body keys
        ct = response.headers.get("Content-Type","")
        try:
            if "application/json" in ct:
                j = response.json()
                for k in ("processed","executed","task_id","job_id","command"):
                    if k in j:
                        findings.append({
                            "type":"execution-hint",
                            "message":f"Server JSON response contains '{k}' key indicating processing",
                            "value": j.get(k)
                        })
        except Exception:
            pass

        # Header clues
        headers = response.headers
        if any(k.lower().startswith("x-") for k in headers.keys()):
            # but only record verbose clue
            findings.append({
                "type":"response-headers",
                "message":"Response included custom X- headers; investigate for processing pipeline",
                "headers": dict(headers)
            })

        # Body clues
        body = response.text if hasattr(response, "text") else ""
        for phrase in ("executed","running","started","task","error while executing"):
            if phrase in body.lower():
                findings.append({
                    "type":"body-hint",
                    "message":f"Response body contains phrase '{phrase}' suggestive of execution/processing"
                })
        return findings

    def scan_site(self, base_url: str):
        """
        Full HTTP scan combining discovery, safe upload probe, and heuristics.
        Returns list of findings
        """
        findings = []
        base_url = base_url.rstrip("/")
        forms = self.discover_upload_forms(base_url, crawl_depth=1)
        if not forms:
            # still look for common upload endpoints (conservative)
            common_paths = ["/upload","/api/upload","/files/upload"]
            for p in common_paths:
                candidate = base_url + p
                r = self._get_page(candidate)
                if r and r.status_code == 200:
                    forms.append({
                        "page": candidate,
                        "action": candidate,
                        "enctype": "multipart/form-data",
                        "method": "post",
                        "fields": {"file":"file"}
                    })

        for form in forms:
            action = form["action"]
            log.info(f"Found upload form: {action} (method={form['method']})")
            # prepare probe filename with executable extension to test filename handling
            marker = make_marker()
            # choose probe filename with executable extension (but content plain text)
            candidate_exts = [".php", ".pl", ".sh", ".exe", ".dll", ".so", ".py"]
            # safe_testing: always send plain-text content; do not include code or binary magic bytes
            for ext in candidate_exts:
                fname = f"probe{ext}"
                content = f"ExecSentry-PROBE-MARKER:{marker}\nThis is a harmless probe file. Not executable content."
                r = self.safe_upload_probe(action, file_field_name=next(iter(form["fields"].keys())), filename=fname, content=content)
                if not r:
                    continue
                candidate_url = self.guess_upload_url_from_response(base_url, r)
                upload_findings = self.analyze_upload_response(r, marker)
                entry = {
                    "target": base_url,
                    "check": "upload-probe",
                    "form_action": action,
                    "filename_tested": fname,
                    "status_code": r.status_code if r else None,
                    "candidate_url": candidate_url,
                    "evidence": upload_findings
                }
                findings.append(entry)
                # If a candidate_url was found, attempt to fetch it (safe) and inspect headers/body
                if candidate_url:
                    try:
                        fr = self.session.get(candidate_url, timeout=self.timeout)
                        # If body contains marker, file was served back; if not, execution might have happened (but could also be processed)
                        contains_marker = marker in fr.text
                        header_evidence = self.rules.match_http_headers(fr.headers)
                        findings.append({
                            "target": base_url,
                            "check": "uploaded-file-access",
                            "candidate_url": candidate_url,
                            "status_code": fr.status_code,
                            "contains_marker": contains_marker,
                            "headers": dict(fr.headers),
                            "header_rule_matches": [r.id for r in header_evidence]
                        })
                        # If the server returned HTML rather than raw text and marker missing, that's an indicator
                        if fr.status_code == 200 and not contains_marker:
                            findings.append({
                                "target": base_url,
                                "check": "possible-execution",
                                "message": f"Uploaded file {fname} not returned raw; body differs — may be processed/executed.",
                                "status_code": fr.status_code
                            })
                    except Exception as e:
                        findings.append({"target": base_url, "check": "fetch-uploaded-candidate-failed", "error": str(e)})
                # conservative: try next extension to gather more evidence
                time.sleep(0.5)
        # Also apply header-based http rules on base page
        page = self._get_page(base_url)
        if page:
            hdr_matches = self.rules.match_http_headers(page.headers)
            for r in hdr_matches:
                findings.append({
                    "target": base_url,
                    "check": "http-header-rule",
                    "rule_id": r.id,
                    "rule_title": r.title,
                    "description": r.description
                })
        return findings
