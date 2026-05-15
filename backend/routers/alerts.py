"""
routers/alerts.py — Alert ingestion, listing, and enrichment endpoints.

Endpoints:
  GET  /api/alerts           — paginated list of enriched alerts
  GET  /api/alerts/{id}      — single alert detail
  POST /api/alerts/sync      — pull fresh alerts from Wazuh
  GET  /api/alerts/stats     — dashboard aggregate statistics
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from datetime import datetime, timezone
from typing import Optional
import asyncio

from services.wazuh import get_wazuh_client
from services.openai_analysis import analyse_alert
from models import (
    EnrichedAlert, AlertsListResponse, DashboardStats,
    AIAnalysis, SeverityLevel,
)

router = APIRouter()

# In-memory store (replace with Supabase in production)
_alert_cache: dict[str, EnrichedAlert] = {}


def _wazuh_level_to_severity(level: int) -> SeverityLevel:
    if level >= 13: return SeverityLevel.CRITICAL
    if level >= 10: return SeverityLevel.HIGH
    if level >= 7:  return SeverityLevel.MEDIUM
    if level >= 4:  return SeverityLevel.LOW
    return SeverityLevel.INFO


async def _enrich_and_cache(raw_alert) -> EnrichedAlert:
    """Analyse a single Wazuh alert and store in cache."""
    analysis: AIAnalysis = await analyse_alert(raw_alert)
    enriched = EnrichedAlert(
        id=raw_alert.id,
        timestamp=datetime.fromisoformat(
            raw_alert.timestamp.replace("Z", "+00:00")
        ),
        rule_id=raw_alert.rule.id,
        rule_level=raw_alert.rule.level,
        rule_description=raw_alert.rule.description,
        agent_name=raw_alert.agent.name,
        agent_ip=raw_alert.agent.ip,
        location=raw_alert.location,
        raw_data=raw_alert.data,
        analysis=analysis,
        analyzed_at=datetime.now(timezone.utc),
    )
    _alert_cache[enriched.id] = enriched
    return enriched


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("", response_model=AlertsListResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[SeverityLevel] = None,
    agent: Optional[str] = None,
    search: Optional[str] = None,
):
    """Return paginated, optionally filtered list of enriched alerts."""
    alerts = list(_alert_cache.values())

    # Filters
    if severity:
        alerts = [a for a in alerts if a.analysis and a.analysis.severity == severity]
    if agent:
        alerts = [a for a in alerts if agent.lower() in a.agent_name.lower()]
    if search:
        q = search.lower()
        alerts = [
            a for a in alerts
            if q in a.rule_description.lower()
            or q in (a.analysis.summary if a.analysis else "").lower()
        ]

    # Sort newest first
    alerts.sort(key=lambda a: a.timestamp, reverse=True)

    total = len(alerts)
    start = (page - 1) * page_size
    paginated = alerts[start : start + page_size]

    return AlertsListResponse(
        alerts=paginated,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/stats", response_model=DashboardStats)
async def get_stats():
    """Aggregate stats for dashboard overview cards."""
    from collections import Counter

    alerts = list(_alert_cache.values())

    severity_counts = Counter(
        a.analysis.severity for a in alerts if a.analysis
    )

    # Alerts by hour (last 24h, bucketed)
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    hourly: dict[int, int] = {h: 0 for h in range(24)}
    for a in alerts:
        diff = now - a.timestamp
        if diff.total_seconds() < 86400:
            hour_bucket = int(diff.total_seconds() // 3600)
            hourly[23 - hour_bucket] = hourly.get(23 - hour_bucket, 0) + 1

    rule_counter = Counter(
        (a.rule_id, a.rule_description) for a in alerts
    )
    top_rules = [
        {"rule_id": k[0], "description": k[1], "count": v}
        for k, v in rule_counter.most_common(5)
    ]

    agents = {a.agent_name for a in alerts}

    return DashboardStats(
        total_alerts_24h=len(alerts),
        critical_count=severity_counts.get(SeverityLevel.CRITICAL, 0),
        high_count=severity_counts.get(SeverityLevel.HIGH, 0),
        medium_count=severity_counts.get(SeverityLevel.MEDIUM, 0),
        low_count=severity_counts.get(SeverityLevel.LOW, 0),
        active_agents=len(agents),
        alerts_by_hour=[{"hour": h, "count": c} for h, c in sorted(hourly.items())],
        top_rules=top_rules,
    )


@router.post("/sync")
async def sync_alerts(background_tasks: BackgroundTasks):
    """Pull fresh alerts from Wazuh and enrich them with AI analysis."""
    wazuh = get_wazuh_client()
    raw_alerts = await wazuh.fetch_alerts(limit=50)

    async def _bulk_enrich():
        tasks = [_enrich_and_cache(a) for a in raw_alerts]
        await asyncio.gather(*tasks, return_exceptions=True)

    background_tasks.add_task(_bulk_enrich)

    return {
        "message": f"Syncing {len(raw_alerts)} alerts in background",
        "count": len(raw_alerts),
    }


@router.get("/{alert_id}", response_model=EnrichedAlert)
async def get_alert(alert_id: str):
    """Return a single enriched alert by ID."""
    alert = _alert_cache.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
