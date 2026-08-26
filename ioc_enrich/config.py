"""Configuration loading for the IOC enrichment tool.

Reads API credentials and runtime settings from a local `.env` file (never
committed — see .gitignore). All secrets are centralised here so the rest of
the package never touches ``os.environ`` directly.

A missing key is left as an empty string; the corresponding client treats that
as an ``invalid_key`` non-vote (DESIGN §10.D) rather than crashing.
"""
from __future__ import annotations

import os

from dotenv import load_dotenv

# Load .env from the current working directory / project root if present.
# No-op (returns False) when the file is absent, so real env vars still work.
load_dotenv()

# --- API credentials ---------------------------------------------------------
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "")

# --- HTTP settings -----------------------------------------------------------
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "15"))  # seconds, per request
# Bounded retries on transient failures (429 / 5xx / connection). 0 disables.
HTTP_RETRIES = int(os.getenv("HTTP_RETRIES", "2"))

# AbuseIPDB report lookback window (days); drives both the confidence score and
# the returned category set. Defaulted to 90 (AbuseIPDB's own doc default).
ABUSEIPDB_MAX_AGE_DAYS = int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"))

# --- API endpoints -----------------------------------------------------------
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{indicator}"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
