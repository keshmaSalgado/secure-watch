from typing import Dict, Any, List
from datetime import datetime

class SecurityChatAssistant:
    def answer_query(self, query: str, context_incident_id: str = None, context_ip: str = None) -> Dict[str, Any]:
        q = query.lower()
        referenced = []
        followups = []

        if "critical" in q or "incidents" in q or "today" in q:
            answer = (
                "**SOC Intelligence Briefing**:\n\n"
                "SecureWatch is currently prioritizing high and critical threat vectors:\n"
                "1. **SEC-2026-0001**: Active Brute-Force Authentication Spray from `198.51.100.42` (Risk Score: 82/100).\n"
                "2. **SEC-2026-0002**: Known Malicious IP activity detected from `198.51.100.79` (Risk Score: 95/100).\n\n"
                "Both incidents involve automated credential stuffing tools attempting to bypass standard authentication."
            )
            referenced = ["SEC-2026-0001", "SEC-2026-0002", "198.51.100.42"]
            followups = [
                "Which IP addresses generated the most suspicious events?",
                "What mitigations are recommended for SEC-2026-0001?",
                "Run an Isolation Forest anomaly scan on recent traffic."
            ]
        elif "ip" in q or "suspicious" in q or "reputation" in q:
            answer = (
                "**Top Hostile IP Addresses**:\n\n"
                "• **198.51.100.42** (Reputation Score: 95/100) - Russian Federation / Mirax Hosting Network. Marked hostile botnet node.\n"
                "• **185.220.101.5** (Reputation Score: 85/100) - Germany / Tor Exit Node. Anonymized proxy relay.\n"
                "• **203.0.113.88** (Reputation Score: 65/100) - Netherlands / NordVPN Transit node."
            )
            referenced = ["198.51.100.42", "185.220.101.5", "203.0.113.88"]
            followups = [
                "What were the most critical security incidents today?",
                "Explain why 198.51.100.42 was marked as high risk."
            ]
        elif "anomaly" in q or "isolation forest" in q:
            answer = (
                "The **Isolation Forest Unsupervised Anomaly Engine** evaluates multi-dimensional event vectors "
                "(failed login velocity, off-hours deviation, targeted account count, IP rotation rate, and request volume). "
                "Any telemetry point with an anomaly magnitude exceeding 0.70 is flagged as an outlier warranting triaging."
            )
            followups = [
                "Detect anomalies on current telemetry.",
                "Generate a daily threat report."
            ]
        else:
            answer = (
                "I am your **SecureWatch AI Security Copilot**. I analyze threat vectors, explain SIEM alert correlation, "
                "evaluate unsupervised Isolation Forest anomalies, and generate incident remediation plans.\n\n"
                "Try asking:\n"
                "• *'What were the most critical security incidents today?'*\n"
                "• *'Which IP addresses generated the most suspicious events?'*\n"
                "• *'Explain the Isolation Forest anomaly detection algorithm.'*"
            )
            followups = [
                "What were the most critical security incidents today?",
                "Which IP addresses generated the most suspicious events?"
            ]

        return {
            "answer": answer,
            "referenced_entities": referenced,
            "suggested_followups": followups,
            "timestamp_utc": datetime.utcnow().isoformat()
        }

