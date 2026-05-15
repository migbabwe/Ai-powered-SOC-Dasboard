"""
routers/analysis.py — On-demand AI analysis endpoint.
"""
from fastapi import APIRouter, HTTPException
from models import AIAnalysis, AnalyzeAlertRequest
from services.wazuh import get_wazuh_client
from services.openai_analysis import analyse_alert

router = APIRouter()

@router.post("/analyze", response_model=AIAnalysis)
async def analyze_alert_on_demand(req: AnalyzeAlertRequest):
    """Trigger AI analysis for a specific alert ID."""
    wazuh = get_wazuh_client()
    raw_alerts = await wazuh.fetch_alerts(limit=100)
    alert = next((a for a in raw_alerts if a.id == req.alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found in Wazuh")
    return await analyse_alert(alert)
