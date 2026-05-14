"""
models.py — Pydantic schemas for request/response validation.

These are the contracts between frontend ↔ backend ↔ AI.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ─── Wazuh alert (raw, from Wazuh API) ────────────────────────────────────────

class WazuhRule(BaseModel):
    id: str
    level: int
    description: str
    groups: List[str] = []

class WazuhAgent(BaseModel):
    id: str
    name: str
    ip: Optional[str] = None

class RawWazuhAlert(BaseModel):
    id: str
    timestamp: str
    rule: WazuhRule
    agent: WazuhAgent
    manager: dict = {}
    data: dict = {}
    location: Optional[str] = None
    full_log: Optional[str] = None


# ─── AI analysis result ────────────────────────────────────────────────────────

class AIAnalysis(BaseModel):
    severity: SeverityLevel
    summary: str
    business_impact: str
    recommended_actions: List[str]
    confidence: float = Field(ge=0.0, le=1.0, default=0.85)


# ─── Enriched alert (raw + AI) ────────────────────────────────────────────────

class EnrichedAlert(BaseModel):
    id: str
    timestamp: datetime
    rule_id: str
    rule_level: int
    rule_description: str
    agent_name: str
    agent_ip: Optional[str]
    location: Optional[str]
    raw_data: dict
    analysis: Optional[AIAnalysis] = None
    analyzed_at: Optional[datetime] = None


# ─── API request/response wrappers ────────────────────────────────────────────

class AnalyzeAlertRequest(BaseModel):
    alert_id: str
    force_refresh: bool = False

class AlertsListResponse(BaseModel):
    alerts: List[EnrichedAlert]
    total: int
    page: int
    page_size: int

class DashboardStats(BaseModel):
    total_alerts_24h: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    active_agents: int
    alerts_by_hour: List[dict]          # [{hour, count}]
    top_rules: List[dict]               # [{rule_id, description, count}]


# ─── Device / agent ───────────────────────────────────────────────────────────

class DeviceStatus(str, Enum):
    ACTIVE       = "active"
    DISCONNECTED = "disconnected"
    NEVER_SEEN   = "never_connected"

class Device(BaseModel):
    id: str
    name: str
    ip: Optional[str]
    os: Optional[str]
    status: DeviceStatus
    last_seen: Optional[datetime]
    alert_count_24h: int = 0
    highest_severity: Optional[SeverityLevel] = None
