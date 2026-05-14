"""
routers/devices.py — Agent/device inventory endpoint.
"""
from fastapi import APIRouter
from models import Device, DeviceStatus, SeverityLevel
from services.wazuh import get_wazuh_client
from datetime import datetime, timezone

router = APIRouter()

@router.get("", response_model=list[Device])
async def list_devices():
    """Return list of Wazuh agents with their current status."""
    wazuh = get_wazuh_client()
    alerts = await wazuh.fetch_alerts(limit=200)

    # Build device map from alert data
    devices: dict[str, Device] = {}
    for alert in alerts:
        aid = alert.agent.id
        if aid not in devices:
            devices[aid] = Device(
                id=aid,
                name=alert.agent.name,
                ip=alert.agent.ip,
                os=None,
                status=DeviceStatus.ACTIVE,
                last_seen=datetime.fromisoformat(
                    alert.timestamp.replace("Z", "+00:00")
                ),
                alert_count_24h=0,
                highest_severity=None,
            )
        devices[aid].alert_count_24h += 1

    return list(devices.values())
