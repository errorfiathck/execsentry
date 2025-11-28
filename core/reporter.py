"""
Reporter: writes JSON and TXT reports
"""
import json
from datetime import datetime
from core.utils import log

class Reporter:
    def write_json(self, path: str, payload):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        log.info(f"JSON report written to {path}")

    def write_txt(self, path: str, payload):
        lines = []
        meta = payload.get("meta",{})
        lines.append(f"ExecSentry Report - {datetime.utcnow().isoformat()}Z")
        lines.append(f"Tool: {meta.get('tool')} - Safe testing: {meta.get('safe_testing')}")
        lines.append("="*60)
        findings = payload.get("findings", [])
        for i, f in enumerate(findings):
            lines.append(f"[{i+1}] Type: {f.get('check') or f.get('type') or 'finding'}")
            for k,v in f.items():
                lines.append(f"    {k}: {v}")
            lines.append("-"*40)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        log.info(f"TXT report written to {path}")
