"""
services/openai_analysis.py — OpenAI integration for alert triage.

Strategy:
- Build a rich structured prompt from the Wazuh alert
- Use function calling / JSON mode to guarantee structured output
- Cache results in Supabase to avoid re-analysing the same alert
- Graceful degradation: if OpenAI fails, return a rule-based fallback
"""

import json
import logging
from typing import Optional

from openai import AsyncOpenAI

from config import settings
from models import AIAnalysis, SeverityLevel, RawWazuhAlert

logger = logging.getLogger(__name__)

client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)


# ─── Severity mapping from Wazuh rule level ───────────────────────────────────

def _level_to_severity(level: int) -> SeverityLevel:
    if level >= 13:  return SeverityLevel.CRITICAL
    if level >= 10:  return SeverityLevel.HIGH
    if level >= 7:   return SeverityLevel.MEDIUM
    if level >= 4:   return SeverityLevel.LOW
    return SeverityLevel.INFO


# ─── Prompt builder ───────────────────────────────────────────────────────────

def _build_prompt(alert: RawWazuhAlert) -> str:
    return f"""You are an expert SOC (Security Operations Center) analyst.
Analyse the following Wazuh security alert and respond ONLY with a JSON object — no markdown, no explanation.

ALERT DETAILS:
- Rule ID: {alert.rule.id}
- Rule Level: {alert.rule.level}/15 (15 = most critical)
- Rule Description: {alert.rule.description}
- Rule Groups: {", ".join(alert.rule.groups)}
- Affected Agent: {alert.agent.name} ({alert.agent.ip or "IP unknown"})
- Event Location: {alert.location or "unknown"}
- Raw Event Data: {json.dumps(alert.data, indent=2)}
- Full Log Entry: {alert.full_log or "not available"}

Respond with this exact JSON schema:
{{
  "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
  "summary": "<2-3 sentence plain-English explanation of what happened and why it matters>",
  "business_impact": "<1-2 sentences on potential business/operational risk if unaddressed>",
  "recommended_actions": [
    "<immediate action 1>",
    "<immediate action 2>",
    "<follow-up action>"
  ],
  "confidence": <float 0.0-1.0 indicating your confidence in the analysis>
}}

Rules:
- severity must reflect both the Wazuh rule level AND the actual threat context
- summary must be jargon-free enough for a non-technical manager to understand
- recommended_actions must be specific, actionable, and prioritised
- Never invent facts not present in the alert data"""


# ─── Main analysis function ───────────────────────────────────────────────────

async def analyse_alert(alert: RawWazuhAlert) -> AIAnalysis:
    """
    Send alert to OpenAI and return structured AIAnalysis.
    Falls back to rule-based analysis if API call fails.
    """
    if not settings.OPENAI_API_KEY:
        logger.warning("No OpenAI API key — using rule-based fallback analysis")
        return _fallback_analysis(alert)

    try:
        response = await client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert SOC analyst. Always respond with valid JSON only.",
                },
                {
                    "role": "user",
                    "content": _build_prompt(alert),
                },
            ],
            temperature=0.2,      # low temp → consistent, factual output
            max_tokens=600,
        )

        raw_json = response.choices[0].message.content
        data = json.loads(raw_json)

        return AIAnalysis(
            severity=SeverityLevel(data.get("severity", "MEDIUM")),
            summary=data.get("summary", ""),
            business_impact=data.get("business_impact", ""),
            recommended_actions=data.get("recommended_actions", []),
            confidence=float(data.get("confidence", 0.85)),
        )

    except Exception as exc:
        logger.error(f"OpenAI analysis failed for alert {alert.id}: {exc}")
        return _fallback_analysis(alert)


def _fallback_analysis(alert: RawWazuhAlert) -> AIAnalysis:
    """Rule-based fallback when OpenAI is unavailable."""
    severity = _level_to_severity(alert.rule.level)
    return AIAnalysis(
        severity=severity,
        summary=(
            f"Wazuh rule '{alert.rule.description}' triggered on agent "
            f"'{alert.agent.name}'. Rule level {alert.rule.level}/15 "
            f"classified as {severity.value}. AI analysis unavailable — "
            f"manual investigation recommended."
        ),
        business_impact=(
            "Unable to determine business impact automatically. "
            "Please review the raw alert data and consult your security runbook."
        ),
        recommended_actions=[
            f"Review the raw log on agent {alert.agent.name}",
            "Check for related alerts in the same time window",
            "Consult the Wazuh rule documentation for rule ID " + alert.rule.id,
            "Escalate to Tier 2 if activity cannot be explained",
        ],
        confidence=0.4,
    )
