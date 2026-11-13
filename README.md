# Attack Graph Generator

An automated network security assessment and attack surface visualization platform built with Python and Streamlit.

## Features

- **Host Discovery:** Parallel ICMP ping scanner to discover active hosts on local subnets (e.g. `192.168.1.0/24`).
- **Multi-threaded Port Scanner:** Fast TCP socket scanning across standard, common, or full 65,535 port ranges.
- **Service & Heuristic OS Detection:** Identifies services (SMB, SSH, HTTP, DBs, CWMP, etc.) and infers host OS.
- **Security Findings Engine:** Rule-based heuristics highlighting unencrypted, exposed, or risky services.
- **Risk Calculation Engine:** Computes risk scores and ratings (LOW, MEDIUM, HIGH, CRITICAL).
- **Interactive PyVis Attack Graph:** Visualizes attack paths: `Host -> Port -> Service -> Finding -> Risk Path`.
- **Cyber Modern Web Dashboard:** Streamlit UI with real-time streaming progress, live console logs, and host explorer.

## Quick Start

### 1. Web Dashboard (Recommended)

```bash
.\.venv\Scripts\streamlit run web_app.py
```
Open your browser at `http://localhost:8501`.

### 2. Command-Line Interface (CLI)

```bash
.\.venv\Scripts\python main.py
```
Enter your target network CIDR (e.g. `192.168.31.0/24`) when prompted.
