# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HTTPS Doctor (https_doctor) is a desktop tool for detecting and diagnosing HTTPS certificate status. It checks certificate chain integrity, expiry dates, revocation status, domain matching, TLS version, and cipher suites.

## Commands

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run the Application
```bash
python main.py
```

### Build Executable (Windows)
```bash
pyinstaller --onefile --windowed main.py
```

## Architecture

### Module Structure

```
https_doctor/
├── main.py           # Entry point - imports gui and runs App
├── gui.py            # wxPython GUI - MainFrame (UI logic only)
├── cert_checker.py   # Core detection logic - pure functions, no GUI dependency
├── report_generator.py  # HTML report generation
└── requirements.txt
```

### Key Design Points

**cert_checker.py** is the core engine - a pure function library with no GUI dependencies. The main function is `check_certificate(url: str) -> dict` which returns structured results including:
- `status`: "valid" | "warning" | "error"
- `cert_chain`: list of {type, name, status} for root/intermediate/server certs
- `cert_chain_complete`: bool
- `expiry`: {expired, days_left, expire_date}
- `revocation`: {status, ocsp_response}
- `domain_match`: {match, cert_cn, cert_san}
- `tls`: {version, cipher_suite, key_exchange}

**gui.py** imports cert_checker and report_generator. Uses threading to run certificate checks in a worker thread, communicating results back to the main wxPython thread via `wx.CallAfter`.

**report_generator.py** takes the results list from cert_checker and generates a self-contained HTML report with embedded CSS.

### GUI Framework
- wxPython for the desktop GUI
- Uses `wx.lib.agw.flatnotebook` for tabbed detail panel (Cert Chain, TLS Info, Domain Validation)
- Threading model: UI runs on main thread, certificate checks run on worker threads
