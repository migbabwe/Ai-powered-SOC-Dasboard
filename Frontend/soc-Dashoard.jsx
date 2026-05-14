import { useState, useEffect, useCallback } from "react";
import { AlertTriangle, Shield, Activity, Server, Search, RefreshCw, ChevronRight, X, Zap, Eye, Clock, TrendingUp, Wifi, WifiOff, Terminal, Lock } from "lucide-react";

// ─── Mock data (mirrors backend mock alerts) ───────────────────────────────
const MOCK_ALERTS = [
  {
    id: "alert_001", timestamp: "2024-01-15T14:32:01.000Z",
    rule_id: "5503", rule_level: 10, rule_description: "User login attempt (SSH) — brute force pattern",
    agent_name: "prod-web-01", agent_ip: "10.0.1.10", location: "/var/log/auth.log",
    analysis: {
      severity: "HIGH",
      summary: "A brute-force SSH login attack originating from a known Tor exit node (185.220.101.47) targeted the root account on your primary web server. Over 200 failed attempts were logged in a 5-minute window.",
      business_impact: "If successful, an attacker gains root access to your production web server, potentially exposing all customer data and enabling full infrastructure takeover.",
      recommended_actions: [
        "Immediately block IP 185.220.101.47 at the firewall level",
        "Disable root SSH login in /etc/ssh/sshd_config (PermitRootLogin no)",
        "Enable SSH key-based auth only and disable password authentication",
        "Review /var/log/auth.log for any successful logins in the past 24h",
        "Consider deploying fail2ban or CrowdSec for automated blocking",
      ],
      confidence: 0.94,
    },
  },
  {
    id: "alert_002", timestamp: "2024-01-15T14:28:15.000Z",
    rule_id: "31103", rule_level: 12, rule_description: "Web attack: SQL injection attempt detected",
    agent_name: "prod-web-01", agent_ip: "10.0.1.10", location: "/var/log/nginx/access.log",
    analysis: {
      severity: "CRITICAL",
      summary: "A SQL injection attack was detected against your public API endpoint. The attacker attempted to extract all user records using a classic UNION-based injection payload. The request returned a 200 status, suggesting partial success.",
      business_impact: "A successful SQL injection could expose your entire user database including PII, credentials, and payment data — triggering GDPR/PCI-DSS breach notification obligations.",
      recommended_actions: [
        "URGENT: Check database query logs for data exfiltration immediately",
        "Block IP 203.0.113.42 and audit all requests from this source in the last 7 days",
        "Review the /api/users endpoint for parameterized query usage",
        "Deploy a WAF rule to block SQLi patterns",
        "Notify your DPO if any data exposure is confirmed",
      ],
      confidence: 0.97,
    },
  },
  {
    id: "alert_003", timestamp: "2024-01-15T14:20:44.000Z",
    rule_id: "554", rule_level: 7, rule_description: "File added to the system — suspicious binary",
    agent_name: "prod-db-01", agent_ip: "10.0.1.20", location: "syscheck",
    analysis: {
      severity: "HIGH",
      summary: "Netcat (nc) was added to /usr/bin on your production database server as root. Netcat is a networking utility commonly used by attackers to establish backdoor connections and exfiltrate data.",
      business_impact: "An attacker may be establishing a persistent backdoor on your database server, enabling future data theft without re-exploitation.",
      recommended_actions: [
        "Remove /usr/bin/nc immediately and check for active connections: netstat -tlnp",
        "Check bash history for all users: cat /root/.bash_history",
        "Audit recent logins: last -a | head -20",
        "Run a full rootkit scan with chkrootkit or rkhunter",
        "Isolate the host from the network pending full forensic investigation",
      ],
      confidence: 0.88,
    },
  },
  {
    id: "alert_004", timestamp: "2024-01-15T14:15:09.000Z",
    rule_id: "40101", rule_level: 15, rule_description: "Rootkit detected: suspicious kernel module loaded",
    agent_name: "prod-db-01", agent_ip: "10.0.1.20", location: "rootcheck",
    analysis: {
      severity: "CRITICAL",
      summary: "Diamorphine, a well-known Linux rootkit that hides processes and files from the OS, was detected on your production database server. This indicates a complete system compromise — the attacker has kernel-level control.",
      business_impact: "Full system compromise at kernel level. The attacker can hide all activity, intercept network traffic, steal encryption keys, and access all database contents invisibly. This is a P0 incident.",
      recommended_actions: [
        "IMMEDIATE: Isolate prod-db-01 from the network NOW — pull the virtual NIC",
        "Do NOT attempt to clean — the system is untrustworthy. Preserve for forensics then rebuild",
        "Initiate your incident response plan and notify CISO",
        "Rotate all database credentials, API keys, and secrets immediately",
        "Restore from the last known-good backup after rebuilding the host",
        "Conduct a full compromise assessment across all systems that touched this host",
      ],
      confidence: 0.99,
    },
  },
  {
    id: "alert_005", timestamp: "2024-01-15T14:10:33.000Z",
    rule_id: "87103", rule_level: 6, rule_description: "M365: Unusual login location detected",
    agent_name: "m365-connector", agent_ip: "10.0.1.5", location: "ms365",
    analysis: {
      severity: "MEDIUM",
      summary: "Your CFO's Microsoft 365 account logged in from Russia (IP 45.33.32.156) — a location never previously seen for this user. This could indicate account compromise via phishing or credential stuffing.",
      business_impact: "If the CFO account is compromised, the attacker gains access to sensitive financial data, executive communications, and may be able to approve fraudulent wire transfers.",
      recommended_actions: [
        "Contact the CFO directly (not by email) to confirm if they are traveling",
        "If not confirmed legitimate: revoke all active sessions in Azure AD immediately",
        "Enable MFA if not already active on this account",
        "Review mailbox rules for any auto-forwarding rules created recently",
        "Check for any large file downloads or SharePoint access in the last 24h",
      ],
      confidence: 0.81,
    },
  },
  {
    id: "alert_006", timestamp: "2024-01-15T14:05:22.000Z",
    rule_id: "2932", rule_level: 5, rule_description: "Firewall dropped inbound RDP attempt",
    agent_name: "fw-edge-01", agent_ip: "10.0.0.1", location: "firewall",
    analysis: {
      severity: "LOW",
      summary: "Your edge firewall blocked an inbound RDP (port 3389) connection attempt from an external IP. This is common internet background noise but worth logging for trend analysis.",
      business_impact: "Currently blocked with no immediate risk. However, repeated attempts may indicate targeted reconnaissance of your perimeter.",
      recommended_actions: [
        "No immediate action required — the firewall correctly blocked the attempt",
        "Ensure RDP is not exposed directly to the internet on any host",
        "If RDP access is needed externally, use a VPN or jump host instead",
        "Monitor for escalating frequency from this IP range",
      ],
      confidence: 0.92,
    },
  },
];

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#FF3B3B", bg: "rgba(255,59,59,0.12)", border: "rgba(255,59,59,0.3)", glow: "rgba(255,59,59,0.4)", label: "CRITICAL", dot: "#FF3B3B" },
  HIGH:     { color: "#FF8C00", bg: "rgba(255,140,0,0.12)",  border: "rgba(255,140,0,0.3)",  glow: "rgba(255,140,0,0.4)",  label: "HIGH",     dot: "#FF8C00" },
  MEDIUM:   { color: "#FFD700", bg: "rgba(255,215,0,0.10)",  border: "rgba(255,215,0,0.3)",  glow: "rgba(255,215,0,0.3)",  label: "MEDIUM",   dot: "#FFD700" },
  LOW:      { color: "#00C8FF", bg: "rgba(0,200,255,0.08)",  border: "rgba(0,200,255,0.25)", glow: "rgba(0,200,255,0.3)",  label: "LOW",      dot: "#00C8FF" },
  INFO:     { color: "#6B7280", bg: "rgba(107,114,128,0.1)", border: "rgba(107,114,128,0.2)",glow: "rgba(107,114,128,0.2)",label: "INFO",     dot: "#6B7280" },
};

function timeAgo(ts) {
  const diff = (Date.now() - new Date(ts)) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

// ─── Sidebar ───────────────────────────────────────────────────────────────
function Sidebar({ activeView, setActiveView }) {
  const nav = [
    { id: "dashboard", icon: Activity, label: "Overview" },
    { id: "alerts",    icon: AlertTriangle, label: "Alert Feed" },
    { id: "devices",   icon: Server, label: "Devices" },
    { id: "analysis",  icon: Zap, label: "AI Analysis" },
  ];
  return (
    <aside style={{
      width: 220, minHeight: "100vh", background: "#0A0C10",
      borderRight: "1px solid rgba(255,255,255,0.06)",
      display: "flex", flexDirection: "column",
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
    }}>
      {/* Logo */}
      <div style={{ padding: "24px 20px 20px", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: "linear-gradient(135deg, #00C8FF, #0066FF)",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 0 16px rgba(0,200,255,0.4)",
          }}>
            <Shield size={16} color="#fff" />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", letterSpacing: "0.05em" }}>SENTINEL</div>
            <div style={{ fontSize: 9, color: "#00C8FF", letterSpacing: "0.15em" }}>AI · SOC</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: "12px 10px" }}>
        {nav.map(({ id, icon: Icon, label }) => {
          const active = activeView === id;
          return (
            <button key={id} onClick={() => setActiveView(id)} style={{
              width: "100%", display: "flex", alignItems: "center", gap: 10,
              padding: "10px 12px", borderRadius: 8, border: "none", cursor: "pointer",
              marginBottom: 2,
              background: active ? "rgba(0,200,255,0.1)" : "transparent",
              color: active ? "#00C8FF" : "#6B7280",
              fontSize: 12, fontWeight: active ? 600 : 400,
              letterSpacing: "0.05em", transition: "all 0.15s ease",
              borderLeft: active ? "2px solid #00C8FF" : "2px solid transparent",
            }}>
              <Icon size={15} />
              {label}
            </button>
          );
        })}
      </nav>

      {/* Status indicator */}
      <div style={{ padding: "16px 20px", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 10, color: "#4B5563" }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#22C55E", boxShadow: "0 0 6px #22C55E" }} />
          WAZUH CONNECTED
        </div>
        <div style={{ fontSize: 9, color: "#374151", marginTop: 4, letterSpacing: "0.08em" }}>
          LAST SYNC: 2m ago
        </div>
      </div>
    </aside>
  );
}

// ─── Stat card ─────────────────────────────────────────────────────────────
function StatCard({ label, value, color, icon: Icon, sublabel }) {
  return (
    <div style={{
      background: "#0D0F14", border: "1px solid rgba(255,255,255,0.06)",
      borderRadius: 12, padding: "20px 24px",
      borderTop: `2px solid ${color}`,
      position: "relative", overflow: "hidden",
    }}>
      <div style={{
        position: "absolute", top: 0, right: 0, width: 80, height: 80,
        background: `radial-gradient(circle at top right, ${color}15, transparent 70%)`,
      }} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ fontSize: 11, color: "#6B7280", letterSpacing: "0.1em", fontFamily: "monospace", marginBottom: 8 }}>
            {label}
          </div>
          <div style={{ fontSize: 36, fontWeight: 700, color, lineHeight: 1, fontFamily: "monospace" }}>
            {value}
          </div>
          {sublabel && <div style={{ fontSize: 10, color: "#4B5563", marginTop: 6 }}>{sublabel}</div>}
        </div>
        <div style={{
          width: 36, height: 36, borderRadius: 8,
          background: `${color}18`, border: `1px solid ${color}30`,
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <Icon size={16} color={color} />
        </div>
      </div>
    </div>
  );
}

// ─── Severity badge ─────────────────────────────────────────────────────────
function SeverityBadge({ severity, size = "sm" }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.INFO;
  const pad = size === "lg" ? "6px 14px" : "3px 8px";
  const fs = size === "lg" ? 11 : 9;
  return (
    <span style={{
      background: cfg.bg, border: `1px solid ${cfg.border}`,
      color: cfg.color, borderRadius: 4, padding: pad,
      fontSize: fs, fontWeight: 700, letterSpacing: "0.1em",
      fontFamily: "monospace", whiteSpace: "nowrap",
      boxShadow: `0 0 8px ${cfg.glow}`,
    }}>
      {cfg.label}
    </span>
  );
}

// ─── Sparkline bar chart ────────────────────────────────────────────────────
function MiniBarChart({ data }) {
  const max = Math.max(...data.map(d => d.count), 1);
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 3, height: 48 }}>
      {data.slice(-24).map((d, i) => (
        <div key={i} style={{
          flex: 1, borderRadius: "2px 2px 0 0",
          height: `${Math.max((d.count / max) * 100, 4)}%`,
          background: d.count > 0
            ? `rgba(0,200,255,${0.3 + (d.count / max) * 0.7})`
            : "rgba(255,255,255,0.04)",
          transition: "height 0.3s ease",
          minWidth: 4,
        }} />
      ))}
    </div>
  );
}

// ─── Alert row ─────────────────────────────────────────────────────────────
function AlertRow({ alert, onSelect, selected }) {
  const cfg = SEVERITY_CONFIG[alert.analysis?.severity] || SEVERITY_CONFIG.INFO;
  const isSelected = selected?.id === alert.id;
  return (
    <div onClick={() => onSelect(alert)} style={{
      display: "grid", gridTemplateColumns: "120px 1fr 130px 100px 80px 32px",
      alignItems: "center", gap: 16,
      padding: "12px 20px", cursor: "pointer",
      background: isSelected ? "rgba(0,200,255,0.06)" : "transparent",
      borderLeft: isSelected ? "2px solid #00C8FF" : "2px solid transparent",
      borderBottom: "1px solid rgba(255,255,255,0.04)",
      transition: "all 0.15s ease",
    }}
    onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = "rgba(255,255,255,0.02)"; }}
    onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = "transparent"; }}
    >
      <SeverityBadge severity={alert.analysis?.severity} />
      <div>
        <div style={{ fontSize: 12, color: "#E5E7EB", marginBottom: 2, fontWeight: 500 }}>
          {alert.rule_description}
        </div>
        <div style={{ fontSize: 10, color: "#4B5563", fontFamily: "monospace" }}>
          Rule {alert.rule_id} · {alert.location}
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <Server size={11} color="#6B7280" />
        <span style={{ fontSize: 11, color: "#9CA3AF", fontFamily: "monospace" }}>
          {alert.agent_name}
        </span>
      </div>
      <div style={{ fontSize: 10, color: "#4B5563", fontFamily: "monospace" }}>
        {alert.agent_ip}
      </div>
      <div style={{ fontSize: 10, color: "#4B5563", fontFamily: "monospace" }}>
        {timeAgo(alert.timestamp)}
      </div>
      <ChevronRight size={14} color={isSelected ? "#00C8FF" : "#374151"} />
    </div>
  );
}

// ─── AI Analysis Panel ─────────────────────────────────────────────────────
function AnalysisPanel({ alert, onClose }) {
  if (!alert) return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      height: "100%", gap: 12, color: "#374151",
    }}>
      <Shield size={40} strokeWidth={1} color="#1F2937" />
      <div style={{ fontSize: 12, fontFamily: "monospace", textAlign: "center", lineHeight: 1.6 }}>
        SELECT AN ALERT<br />TO VIEW AI ANALYSIS
      </div>
    </div>
  );

  const { analysis } = alert;
  const cfg = SEVERITY_CONFIG[analysis?.severity] || SEVERITY_CONFIG.INFO;

  return (
    <div style={{ height: "100%", overflowY: "auto", padding: "20px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 10, color: "#4B5563", fontFamily: "monospace", letterSpacing: "0.1em", marginBottom: 6 }}>
            AI THREAT ANALYSIS
          </div>
          <SeverityBadge severity={analysis?.severity} size="lg" />
        </div>
        <button onClick={onClose} style={{
          background: "none", border: "none", color: "#6B7280", cursor: "pointer", padding: 4,
        }}>
          <X size={16} />
        </button>
      </div>

      {/* Alert meta */}
      <div style={{
        background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
        borderRadius: 8, padding: "12px 16px", marginBottom: 16,
        fontFamily: "monospace", fontSize: 10,
      }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px 16px" }}>
          {[
            ["AGENT", alert.agent_name],
            ["IP", alert.agent_ip || "—"],
            ["RULE ID", alert.rule_id],
            ["RULE LEVEL", `${alert.rule_level}/15`],
            ["LOCATION", alert.location || "—"],
            ["CONFIDENCE", `${Math.round((analysis?.confidence || 0) * 100)}%`],
          ].map(([k, v]) => (
            <div key={k}>
              <span style={{ color: "#4B5563" }}>{k}: </span>
              <span style={{ color: "#9CA3AF" }}>{v}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Summary */}
      <Section title="THREAT SUMMARY" color="#00C8FF">
        <p style={{ fontSize: 13, color: "#D1D5DB", lineHeight: 1.7, margin: 0 }}>
          {analysis?.summary}
        </p>
      </Section>

      {/* Business impact */}
      <Section title="BUSINESS IMPACT" color={cfg.color}>
        <div style={{
          background: cfg.bg, border: `1px solid ${cfg.border}`,
          borderRadius: 6, padding: "10px 14px",
        }}>
          <p style={{ fontSize: 12, color: cfg.color, lineHeight: 1.6, margin: 0 }}>
            {analysis?.business_impact}
          </p>
        </div>
      </Section>

      {/* Recommended actions */}
      <Section title="RECOMMENDED ACTIONS" color="#22C55E">
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {analysis?.recommended_actions.map((action, i) => (
            <div key={i} style={{
              display: "flex", gap: 10, alignItems: "flex-start",
              background: "rgba(34,197,94,0.05)", border: "1px solid rgba(34,197,94,0.12)",
              borderRadius: 6, padding: "8px 12px",
            }}>
              <div style={{
                minWidth: 18, height: 18, borderRadius: "50%",
                background: "rgba(34,197,94,0.15)", border: "1px solid rgba(34,197,94,0.3)",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 9, color: "#22C55E", fontWeight: 700, fontFamily: "monospace",
              }}>
                {i + 1}
              </div>
              <span style={{ fontSize: 12, color: "#D1D5DB", lineHeight: 1.5 }}>{action}</span>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
}

function Section({ title, color, children }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{
        fontSize: 9, color, letterSpacing: "0.15em", fontFamily: "monospace",
        fontWeight: 700, marginBottom: 10, display: "flex", alignItems: "center", gap: 6,
      }}>
        <div style={{ width: 12, height: 1, background: color, opacity: 0.5 }} />
        {title}
      </div>
      {children}
    </div>
  );
}

// ─── Dashboard overview ────────────────────────────────────────────────────
function DashboardView({ alerts }) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  alerts.forEach(a => {
    const s = a.analysis?.severity;
    if (s && counts[s] !== undefined) counts[s]++;
  });
  const agents = [...new Set(alerts.map(a => a.agent_name))];

  // Fake hourly data
  const hourly = Array.from({ length: 24 }, (_, i) => ({
    hour: i,
    count: Math.floor(Math.random() * 8) + (i > 12 && i < 16 ? 10 : 0),
  }));
  hourly[22].count = 12; hourly[21].count = 9;

  const topRules = Object.entries(
    alerts.reduce((acc, a) => {
      const k = a.rule_description;
      acc[k] = (acc[k] || 0) + 1;
      return acc;
    }, {})
  ).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <div>
      {/* Stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 16, marginBottom: 24 }}>
        <StatCard label="TOTAL · 24H" value={alerts.length} color="#00C8FF" icon={Activity} sublabel="All severity levels" />
        <StatCard label="CRITICAL" value={counts.CRITICAL} color="#FF3B3B" icon={AlertTriangle} sublabel="Immediate response" />
        <StatCard label="HIGH" value={counts.HIGH} color="#FF8C00" icon={Shield} sublabel="Urgent review" />
        <StatCard label="ACTIVE AGENTS" value={agents.length} color="#22C55E" icon={Server} sublabel="Reporting endpoints" />
      </div>

      {/* Chart + top rules */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
        <div style={{
          background: "#0D0F14", border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: 12, padding: 20,
        }}>
          <div style={{ fontSize: 10, color: "#4B5563", fontFamily: "monospace", letterSpacing: "0.1em", marginBottom: 16 }}>
            ALERT VOLUME · LAST 24H
          </div>
          <MiniBarChart data={hourly} />
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6, fontSize: 9, color: "#374151", fontFamily: "monospace" }}>
            <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>NOW</span>
          </div>
        </div>

        <div style={{
          background: "#0D0F14", border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: 12, padding: 20,
        }}>
          <div style={{ fontSize: 10, color: "#4B5563", fontFamily: "monospace", letterSpacing: "0.1em", marginBottom: 16 }}>
            TOP TRIGGERED RULES
          </div>
          {topRules.map(([desc, count], i) => (
            <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: "#9CA3AF", flex: 1, marginRight: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {desc}
              </div>
              <div style={{
                fontSize: 10, color: "#00C8FF", fontFamily: "monospace",
                background: "rgba(0,200,255,0.08)", padding: "2px 8px", borderRadius: 4,
              }}>
                {count}x
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Severity distribution */}
      <div style={{
        background: "#0D0F14", border: "1px solid rgba(255,255,255,0.06)",
        borderRadius: 12, padding: 20,
      }}>
        <div style={{ fontSize: 10, color: "#4B5563", fontFamily: "monospace", letterSpacing: "0.1em", marginBottom: 16 }}>
          SEVERITY DISTRIBUTION
        </div>
        <div style={{ display: "flex", gap: 8, height: 8, borderRadius: 4, overflow: "hidden", marginBottom: 12 }}>
          {Object.entries(counts).map(([sev, count]) => {
            const pct = (count / alerts.length) * 100;
            return (
              <div key={sev} style={{
                flex: pct, background: SEVERITY_CONFIG[sev]?.color,
                opacity: 0.8, minWidth: count > 0 ? 4 : 0,
              }} />
            );
          })}
        </div>
        <div style={{ display: "flex", gap: 20 }}>
          {Object.entries(counts).map(([sev, count]) => (
            <div key={sev} style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: SEVERITY_CONFIG[sev]?.color }} />
              <span style={{ fontSize: 10, color: "#6B7280", fontFamily: "monospace" }}>{sev} · {count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Devices view ──────────────────────────────────────────────────────────
function DevicesView({ alerts }) {
  const deviceMap = {};
  alerts.forEach(a => {
    if (!deviceMap[a.agent_name]) {
      deviceMap[a.agent_name] = { name: a.agent_name, ip: a.agent_ip, count: 0, severities: [] };
    }
    deviceMap[a.agent_name].count++;
    if (a.analysis?.severity) deviceMap[a.agent_name].severities.push(a.analysis.severity);
  });

  const devices = Object.values(deviceMap).map(d => ({
    ...d,
    topSeverity: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].find(s => d.severities.includes(s)) || "INFO",
  }));

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 16 }}>
      {devices.map(device => {
        const cfg = SEVERITY_CONFIG[device.topSeverity];
        return (
          <div key={device.name} style={{
            background: "#0D0F14", border: `1px solid ${cfg.border}`,
            borderRadius: 12, padding: 20,
            boxShadow: `0 0 20px ${cfg.glow}20`,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
              <div style={{
                width: 40, height: 40, borderRadius: 10,
                background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
                display: "flex", alignItems: "center", justifyContent: "center",
              }}>
                <Server size={18} color="#6B7280" />
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 9, fontFamily: "monospace" }}>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#22C55E", boxShadow: "0 0 6px #22C55E" }} />
                <span style={{ color: "#22C55E" }}>ACTIVE</span>
              </div>
            </div>
            <div style={{ fontSize: 14, color: "#E5E7EB", fontWeight: 600, fontFamily: "monospace", marginBottom: 4 }}>
              {device.name}
            </div>
            <div style={{ fontSize: 11, color: "#4B5563", fontFamily: "monospace", marginBottom: 16 }}>
              {device.ip || "IP unknown"}
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 9, color: "#4B5563", fontFamily: "monospace", marginBottom: 4 }}>ALERTS</div>
                <div style={{ fontSize: 24, fontWeight: 700, color: cfg.color, fontFamily: "monospace" }}>{device.count}</div>
              </div>
              <SeverityBadge severity={device.topSeverity} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Main App ──────────────────────────────────────────────────────────────
export default function SOCDashboard() {
  const [activeView, setActiveView] = useState("dashboard");
  const [alerts, setAlerts] = useState(MOCK_ALERTS);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [tick, setTick] = useState(0);

  // Live clock tick for "X ago" labels
  useEffect(() => {
    const t = setInterval(() => setTick(n => n + 1), 30000);
    return () => clearInterval(t);
  }, []);

  const handleSync = useCallback(async () => {
    setSyncing(true);
    await new Promise(r => setTimeout(r, 1800));
    setSyncing(false);
  }, []);

  const filtered = alerts.filter(a => {
    const matchSearch = !search ||
      a.rule_description.toLowerCase().includes(search.toLowerCase()) ||
      a.agent_name.toLowerCase().includes(search.toLowerCase()) ||
      (a.analysis?.summary || "").toLowerCase().includes(search.toLowerCase());
    const matchSev = !filterSeverity || a.analysis?.severity === filterSeverity;
    return matchSearch && matchSev;
  });

  const panelWidth = selectedAlert ? 400 : 0;

  return (
    <div style={{
      display: "flex", minHeight: "100vh",
      background: "#080A0E", color: "#E5E7EB",
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 2px; }
        @keyframes pulse-dot { 0%,100%{opacity:1} 50%{opacity:0.3} }
        @keyframes slide-in { from{opacity:0;transform:translateX(20px)} to{opacity:1;transform:translateX(0)} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes glow-pulse { 0%,100%{box-shadow:0 0 4px rgba(0,200,255,0.3)} 50%{box-shadow:0 0 16px rgba(0,200,255,0.6)} }
      `}</style>

      <Sidebar activeView={activeView} setActiveView={setActiveView} />

      {/* Main content */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {/* Topbar */}
        <header style={{
          height: 56, display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "0 24px", borderBottom: "1px solid rgba(255,255,255,0.06)",
          background: "#0A0C10",
        }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: "#E5E7EB", letterSpacing: "0.05em" }}>
              {activeView === "dashboard" && "OVERVIEW"}
              {activeView === "alerts" && "ALERT FEED"}
              {activeView === "devices" && "DEVICE INVENTORY"}
              {activeView === "analysis" && "AI ANALYSIS"}
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{
              display: "flex", alignItems: "center", gap: 6,
              fontSize: 10, color: "#4B5563",
            }}>
              <div style={{
                width: 6, height: 6, borderRadius: "50%", background: "#22C55E",
                animation: "pulse-dot 2s infinite",
              }} />
              LIVE
            </div>
            <button onClick={handleSync} style={{
              display: "flex", alignItems: "center", gap: 6,
              background: "rgba(0,200,255,0.08)", border: "1px solid rgba(0,200,255,0.2)",
              borderRadius: 6, padding: "6px 12px", color: "#00C8FF",
              fontSize: 10, cursor: "pointer", letterSpacing: "0.08em",
              animation: syncing ? "glow-pulse 1s infinite" : "none",
            }}>
              <RefreshCw size={11} style={{ animation: syncing ? "spin 1s linear infinite" : "none" }} />
              {syncing ? "SYNCING..." : "SYNC WAZUH"}
            </button>
          </div>
        </header>

        {/* Body */}
        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
          <div style={{ flex: 1, overflowY: "auto", padding: 24 }}>

            {activeView === "dashboard" && <DashboardView alerts={alerts} />}

            {activeView === "devices" && <DevicesView alerts={alerts} />}

            {activeView === "analysis" && (
              <div style={{
                background: "#0D0F14", border: "1px solid rgba(255,255,255,0.06)",
                borderRadius: 12, padding: 32, textAlign: "center",
              }}>
                <Zap size={40} color="#00C8FF" strokeWidth={1} style={{ marginBottom: 16 }} />
                <div style={{ fontSize: 13, color: "#6B7280", lineHeight: 1.8 }}>
                  Select an alert from the <strong style={{ color: "#9CA3AF" }}>Alert Feed</strong> to view full AI analysis.<br />
                  Each alert is analysed by GPT-4o mini with structured threat intelligence output.
                </div>
              </div>
            )}

            {activeView === "alerts" && (
              <div>
                {/* Search + filter bar */}
                <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                  <div style={{ flex: 1, position: "relative" }}>
                    <Search size={13} color="#4B5563" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }} />
                    <input
                      value={search}
                      onChange={e => setSearch(e.target.value)}
                      placeholder="Search alerts, agents, descriptions..."
                      style={{
                        width: "100%", background: "#0D0F14",
                        border: "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 8, padding: "9px 12px 9px 34px",
                        color: "#E5E7EB", fontSize: 12, outline: "none",
                        fontFamily: "monospace",
                      }}
                    />
                  </div>
                  {["CRITICAL","HIGH","MEDIUM","LOW"].map(sev => {
                    const cfg = SEVERITY_CONFIG[sev];
                    const active = filterSeverity === sev;
                    return (
                      <button key={sev} onClick={() => setFilterSeverity(active ? null : sev)} style={{
                        background: active ? cfg.bg : "rgba(255,255,255,0.02)",
                        border: `1px solid ${active ? cfg.border : "rgba(255,255,255,0.08)"}`,
                        color: active ? cfg.color : "#6B7280",
                        borderRadius: 6, padding: "6px 12px",
                        fontSize: 9, fontWeight: 700, cursor: "pointer",
                        letterSpacing: "0.1em", fontFamily: "monospace",
                        boxShadow: active ? `0 0 8px ${cfg.glow}` : "none",
                        transition: "all 0.15s",
                      }}>
                        {sev}
                      </button>
                    );
                  })}
                </div>

                {/* Table header */}
                <div style={{
                  display: "grid", gridTemplateColumns: "120px 1fr 130px 100px 80px 32px",
                  gap: 16, padding: "8px 20px",
                  fontSize: 9, color: "#374151", letterSpacing: "0.1em", fontWeight: 700,
                  borderBottom: "1px solid rgba(255,255,255,0.06)",
                }}>
                  <span>SEVERITY</span><span>DESCRIPTION</span><span>AGENT</span>
                  <span>IP</span><span>TIME</span><span></span>
                </div>

                {/* Alert rows */}
                <div style={{
                  background: "#0D0F14", border: "1px solid rgba(255,255,255,0.06)",
                  borderRadius: 12, overflow: "hidden",
                }}>
                  {filtered.length === 0 ? (
                    <div style={{ padding: 40, textAlign: "center", color: "#374151", fontSize: 12 }}>
                      No alerts match your filters
                    </div>
                  ) : (
                    filtered.map(alert => (
                      <AlertRow
                        key={alert.id}
                        alert={alert}
                        onSelect={a => { setSelectedAlert(a); setActiveView("alerts"); }}
                        selected={selectedAlert}
                      />
                    ))
                  )}
                </div>

                <div style={{ fontSize: 10, color: "#374151", marginTop: 12, fontFamily: "monospace" }}>
                  Showing {filtered.length} of {alerts.length} alerts
                </div>
              </div>
            )}
          </div>

          {/* AI Panel (slides in) */}
          {selectedAlert && (
            <div style={{
              width: 420, borderLeft: "1px solid rgba(255,255,255,0.06)",
              background: "#0A0C10", overflowY: "auto",
              animation: "slide-in 0.2s ease",
            }}>
              <AnalysisPanel alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
