"""
CyberScore TN — Probe Agent Configuration
Configures AI endpoint discovery, timeouts, and network settings.
"""

import os

# Ollama AI Configuration (Host Inférence Node)
OLLAMA_URL = os.environ.get("OLLAMA_URL") or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:25000"
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")

# Candidate endpoints if primary is not responding
CANDIDATE_AI_URLS = [
    OLLAMA_URL,
    "http://192.168.98.1:25000",  # VMware NAT Gateway IP from VM
    "http://192.168.92.1:25000",  # VMware Host-Only IP from VM
    "http://192.168.98.1:11434",
    "http://192.168.92.1:11434",
    "http://127.0.0.1:25000",
    "http://127.0.0.1:11434",
    "http://192.168.56.1:25000",  # Host-Only IP from inside VirtualBox VM
    "http://192.168.56.1:11434",
    "http://10.0.2.2:25000",      # NAT Gateway IP from inside VirtualBox VM
    "http://10.0.2.2:11434",
    "http://host.docker.internal:25000",
    "http://host.docker.internal:11434",
]

# Network Port Scanning Configuration
COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPC
    135,   # MS-RPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    1521,  # Oracle DB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    6379,  # Redis
    8000,  # Dev HTTP
    8080,  # Alt HTTP / Proxy
    8443,  # Alt HTTPS
    8888,  # Admin HTTP
    9000,  # Sonar / Portainer
    27017, # MongoDB
]

# Common endpoints to inspect during web recon
SENSITIVE_ENDPOINTS = [
    "/robots.txt",
    "/.git/HEAD",
    "/.env",
    "/phpinfo.php",
    "/admin/",
]

# HTTP & Socket Request Timeouts
HTTP_TIMEOUT = 3.5
SOCKET_TIMEOUT = 2.5
