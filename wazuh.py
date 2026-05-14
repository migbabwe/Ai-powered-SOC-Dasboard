"""
services/wazuh.py — Wazuh REST API integration.

Wazuh exposes a REST API on port 55000.
We authenticate with JWT, then pull alerts from the /alerts index via the
Wazuh Indexer (OpenSearch) or via the standard manager API.

This module:
1. Authenticates and caches the JWT token
2. Fetches raw alerts (paginated)
3. Normalises them into RawWazuhAlert objects
4. Falls back to realistic mock data when WAZUH_BASE_URL is not configured
"""

import httpx
import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Optional
from functools import lru_cache

from config import settings
from models import RawWazuhAlert, WazuhRule, WazuhAgent

logger = logging.getLogger(__name__)

# ─── Mock data (used in dev / demo mode) ──────────────────────────────────────

MOCK_ALERTS: List[dict] = [
    {
        "id": "alert_001",
        "timestamp": "2024-01-15T14:32:01.000Z",
        "rule": {"id": "5503", "level": 10, "description": "User login attempt (ssh)", "groups": ["authentication", "ssh"]},
        "agent": {"id": "001", "name": "prod-web-01", "ip": "10.0.1.10"},
        "manager": {"name": "wazuh-manager"},
        "data": {"srcip": "185.220.101.47", "srcuser": "root", "dstuser": "root"},
        "location": "/var/log/auth.log",
        "full_log": "Jan 15 14:32:01 prod-web-01 sshd[12345]: Failed password for root from 185.220.101.47 port 54321 ssh2",
    },
    {
        "id": "alert_002",
        "timestamp": "2024-01-15T14:28:15.000Z",
        "rule": {"id": "31103", "level": 12, "description": "Web attack: SQL injection attempt detected", "groups": ["web", "attack", "sql_injection"]},
        "agent": {"id": "001", "name": "prod-web-01", "ip": "10.0.1.10"},
        "manager": {"name": "wazuh-manager"},
        "data": {"srcip": "203.0.113.42", "url": "/api/users?id=1' OR '1'='1"},
        "location": "/var/log/nginx/access.log",
        "full_log": 'GET /api/users?id=1\' OR \'1\'=\'1 HTTP/1.1 - 203.0.113.42',
    },
    {
        "id": "alert_003",
        "timestamp": "2024-01-15T14:20:44.000Z",
        "rule": {"id": "554", "level": 7, "description": "File added to the system", "groups": ["syscheck", "integrity_checksum_changed"]},
        "agent": {"id": "002", "name": "prod-db-01", "ip": "10.0.1.20"},
        "manager": {"name": "wazuh-manager"},
        "data": {"path": "/usr/bin/nc", "uid": "0", "gid": "0"},
        "location": "syscheck",
        "full_log": "File '/usr/bin/nc' added to the filesystem.",
    },
    {
        "id": "alert_004",
        "timestamp": "2024-01-15T14:15:09.000Z",
        "rule": {"id": "40101", "level": 15, "description": "Rootkit detected: suspicious kernel module loaded", "groups": ["rootcheck", "rootkit"]},
        "agent": {"id": "002", "name": "prod-db-01", "ip": "10.0.1.20"},
        "manager": {"name": "wazuh-manager"},
        "data": {"module": "diamorphine", "pid": "1337"},
        "location": "rootcheck",
        "full_log": "Rootkit 'diamorphine' detected. Suspicious kernel module loaded.",
    },
    {
        "id": "alert_005",
        "timestamp": "2024-01-15T14:10:33.000Z",
        "rule": {"id": "87103", "level": 6, "description": "Microsoft 365: Unusual login location detected", "groups": ["ms365", "authentication"]},
        "agent": {"id": "003", "name": "m365-connector", "ip": "10.0.1.5"},
        "manager": {"name": "wazuh-manager"},
        "data": {"user": "cfo@company.com", "srcip": "45.33.32.156", "country": "RU"},
        "location": "ms365",
        "full_log": "Unusual login for cfo@company.com from RU (45.33.32.156)",
    },
    {
        "id": "alert_006",
        "timestamp": "2024-01-15T14:05:22.000Z",
        "rule": {"id": "2932", "level": 5, "description": "Firewall drop event", "groups": ["firewall"]},
        "agent": {"id": "004", "name": "fw-edge-01", "ip": "10.0.0.1"},
        "manager": {"name": "wazuh-manager"},
        "data": {"srcip": "198.51.100.7", "dstport": "3389", "proto": "TCP"},
        "location": "firewall",
        "full_log": "Firewall dropped TCP 198.51.100.7 -> 10.0.0.1:3389",
    },
]


# ─── Wazuh client ─────────────────────────────────────────────────────────────

class WazuhClient:
    def __init__(self):
        self._token: Optional[str] = None
        self._token_expiry: Optional[float] = None
        self._mock_mode = not settings.WAZUH_PASSWORD  # use mocks if no creds

    async def _get_token(self) -> str:
        """Authenticate with Wazuh and return a cached JWT."""
        import time
        if self._token and self._token_expiry and time.time() < self._token_expiry:
            return self._token

        async with httpx.AsyncClient(verify=settings.WAZUH_VERIFY_SSL) as client:
            resp = await client.post(
                f"{settings.WAZUH_BASE_URL}/security/user/authenticate",
                auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD),
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data["data"]["token"]
            self._token_expiry = time.time() + 800  # tokens last 900s by default
            return self._token

    async def fetch_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        min_level: int = 3,
    ) -> List[RawWazuhAlert]:
        if self._mock_mode:
            logger.info("Wazuh mock mode: returning sample alerts")
            return [self._parse(a) for a in MOCK_ALERTS]

        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}"}

        async with httpx.AsyncClient(verify=settings.WAZUH_VERIFY_SSL) as client:
            resp = await client.get(
                f"{settings.WAZUH_BASE_URL}/alerts",
                headers=headers,
                params={
                    "limit": limit,
                    "offset": offset,
                    "sort": "-timestamp",
                    "q": f"rule.level>={min_level}",
                },
                timeout=15,
            )
            resp.raise_for_status()
            items = resp.json().get("data", {}).get("affected_items", [])
            return [self._parse(item) for item in items]

    def _parse(self, raw: dict) -> RawWazuhAlert:
        rule_data = raw.get("rule", {})
        agent_data = raw.get("agent", {})
        return RawWazuhAlert(
            id=raw.get("id", ""),
            timestamp=raw.get("timestamp", ""),
            rule=WazuhRule(
                id=str(rule_data.get("id", "")),
                level=int(rule_data.get("level", 0)),
                description=rule_data.get("description", ""),
                groups=rule_data.get("groups", []),
            ),
            agent=WazuhAgent(
                id=str(agent_data.get("id", "")),
                name=agent_data.get("name", "unknown"),
                ip=agent_data.get("ip"),
            ),
            manager=raw.get("manager", {}),
            data=raw.get("data", {}),
            location=raw.get("location"),
            full_log=raw.get("full_log"),
        )


# Singleton
_wazuh_client: Optional[WazuhClient] = None

def get_wazuh_client() -> WazuhClient:
    global _wazuh_client
    if _wazuh_client is None:
        _wazuh_client = WazuhClient()
    return _wazuh_client
