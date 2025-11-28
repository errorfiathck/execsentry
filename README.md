<br/>
<p align="center">
  <a href="https://github.com/errorfiathck">
    <img src="./IMG/prof.jpeg" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">ExecSentry</h3>

  <p align="center">
🛡️ ExecSentry — Arbitrary Binary Execution Vulnerability Scanner.
    <br/>
ExecSentry is a professional-grade, rule-based security scanner designed to detect Arbitrary Binary Execution (ABE) vulnerabilities in: Web applications, Backend microservices, Local software components, CI/CD pipelines, Plugin-based systems, Script runners and scheduled tasks
    <br/>
    <br/>
    <a href="https://intsagram.com/error._.fiat">Instagram page</a>
    .
    <a href="https://youtube.com/error_fiat">Youtube chanel</a>
    .
    <a href="https://twitter.com/ErrorFiat">Twitter page</a>
    .
    <a href="https://t.me/hack_authenticator">Telegram chanel</a>
  </p>
</p>

> Unlike anomaly-based or AI-driven security tools, ExecSentry uses purely deterministic, signature-based, and rule-driven analysis—ensuring transparency, reproducibility, and zero false “AI hallucinations.”

<br/>

# 🔥 Features:

## ✅ Rule-Based, Deterministic Detection

ExecSentry detects multiple execution vectors with no ML, no heuristics:

- File upload → execution vulnerabilities

- Path-based execution (/run?file=…)

- Unsafe subprocess calls (system(), popen(), exec())

- Unvalidated script runners

- Unsafe plugin loading (.dll, .so)

- DLL / SO hijacking and path confusion

- Untrusted executable search paths

- Execution inside CI/CD configs

- Cron, job runners, pipeline triggers

## 🕷️ HTTP Scanner

- Detects upload endpoints

- Tests execution behavior with benign stub files

- Scans API endpoints for execution-related parameter names

- Identifies response patterns suggesting execution

## 🗂️ Filesystem Scanner

- Scans for plugin directories

- Identifies untrusted binary load paths

- Detects scripts or binaries executed from user-controlled locations

## 🧪 Safe Testing Mode

 ExecSentry uses stub binaries, dummy scripts, and no real executable code, ensuring safe, non-malicious testing.

## 📄 Config File Analyzer

Supports scanning:

- Dockerfile

- gitlab-ci.yml, github/workflows/*.yml

- Makefile

- package.json scripts

- crontab

- Custom config formats

ExecSentry detects execution instructions referencing external or untrusted user-controlled files.

## 📝 Comprehensive Reporting

Exports results to:

- JSON

- TXT

- Console summaries

Each finding includes:

- Type of vulnerability

- Severity

- Evidence

- Attack path

- Recommended fix

## 🛠️ CLI Interface

Simple and powerful:
```
execsentry --url http://target.com --output report.json
execsentry --scan-local /var/www/app
execsentry --scan-configs config/
```

# 📦 Installation

1. Clone the Repository
```
git clone https://github.com/errorfiathck/execsentry
cd execsentry
```

2. Install dependencies
```
pip install -r requirements.txt
```

# 🚀 Usage

Scan a Web Application
```
python3 execsentry.py --url http://localhost:5005
```

Scan Local Filesystem
```
python3 execsentry.py --scan-local ./myproject
```

Scan Configuration Files Only
```
python3 execsentry.py --scan-configs ./configs
```

Full Scan (Recommended)
```
python3 execsentry.py --url http://localhost:5005 --scan-local . --scan-configs .
```

Output to JSON + TXT
```
python3 execsentry.py --url http://localhost:5005 --out-json report.json --out-txt report.txt
```

# 📁 Project Structure

```
execsentry/
│
├── execsentry.py          # CLI entry point
├── core/
│   ├── http_scanner.py    # Upload & execution vector detection
│   ├── fs_scanner.py      # Local filesystem + plugin path scanning
│   ├── config_scanner.py  # CI/CD & config analysis
│   ├── rules.py           # Rule definitions
│   ├── reporter.py        # JSON/TXT reporting
│   └── logger.py          # Logging system
│
├── examples/
│   └── vulnerable_app.py  # Intentionally vulnerable Flask app
│
└── README.md
```

# 🧩 Detection Logic (Summary)

ExecSentry uses explicit rule signatures such as:

## 🔍 File Upload Execution

- Detect upload endpoints by scanning form fields and routes

- Upload harmless stub binary

- If server attempts execution → Vulnerable

## 🔍 Path-Based Execution

Scan for routes containing keywords:
```
run, exec, execute, trigger, load, module, script, process, binary
```

Query the endpoint with dummy filenames—check for:

- Execution error messages

- Stack traces

- "not executable"

- "permission denied executing"

## 🔍 Unsafe System Calls

Static code scanning identifies:

- os.system()

- subprocess.call()

- Popen() with unvalidated user input

## 🔍 Plugin Loader Abuse

Detect directories containing .so / .dll that are writable or untrusted.

## 🔍 CI/CD Execution Rules

Parse CI configs for:
```
run:
  - ./file
  - custom_binary
```

or:
```
steps:
  - name: execute
    run: user_script.sh
```

# 🛡️ Security Philosophy

- Deterministic detection only

- No machine learning

- No LLM classification

- No exploitation — safe probing only

- No malware generation

- Full transparency and reproducibility

ExecSentry is built for:

- Security researchers

- Penetration testers

- DevSecOps teams

- CI/CD security pipelines

- Security education and research

# 🤝 Contributing

Contributions are welcome!

Feel free to submit:

- New rule signatures

- Additional config parsers

- Plugin path detection improvements

- Test cases

- Bug fixes

# 📜 License

MIT License — Free to use, modify, and distribute.

# ⭐ Support the Project

If you like ExecSentry, consider giving the repo a star ⭐
Your support helps keep the project growing.
