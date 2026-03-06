"""Reporting models and helpers to build structured forensic output.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


# ── Tool detection models ─────────────────────────────────────────────────────

class ToolFinding(BaseModel):
    tool: str
    risk: str
    evidence: List[str]


class OSInfo(BaseModel):
    name: Optional[str] = None
    id: Optional[str] = None
    variant_tags: List[str] = []
    notes: List[str] = []


# ── Timeline models ───────────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    timestamp: str
    source: str
    event_type: str
    detail: str
    severity: str = "info"
    data: Optional[Dict[str, Any]] = None


# ── Deleted file models ───────────────────────────────────────────────────────

class DeletedFinding(BaseModel):
    path: str
    type: str
    detail: str
    severity: str = "medium"


# ── Persistence models ────────────────────────────────────────────────────────

class PersistenceFinding(BaseModel):
    source: str
    category: str
    detail: str
    severity: str = "medium"
    snippet: str = ""


# ── Configuration analysis models ─────────────────────────────────────────────

class ConfigFinding(BaseModel):
    config: str
    category: str
    detail: str
    severity: str = "info"
    snippet: str = ""
    recommendation: str = ""


# ── Service detection models ──────────────────────────────────────────────────

class ServiceFinding(BaseModel):
    name: str
    display_name: str
    description: str = ""
    category: str
    state: str
    exec_start: str = ""
    run_user: str = "root"
    severity: str = "info"
    source: str = "systemd"
    flags: List[str] = []
    unit_path: str = ""


# ── Top-level report ──────────────────────────────────────────────────────────

class ForensicReport(BaseModel):
    os_info: OSInfo
    findings: List[ToolFinding]
    summary: Dict[str, Any] = {}
    timeline: List[TimelineEvent] = []
    deleted: List[DeletedFinding] = []
    persistence: List[PersistenceFinding] = []
    config: List[ConfigFinding] = []
    services: List[ServiceFinding] = []


def build_report(
    os_info: Dict[str, object],
    classified_findings: List[Dict[str, object]],
    timeline: Optional[List[Dict]] = None,
    deleted: Optional[List[Dict]] = None,
    persistence: Optional[List[Dict]] = None,
    config: Optional[List[Dict]] = None,
    services: Optional[List[Dict]] = None,
) -> ForensicReport:
    os_model = OSInfo(
        name=os_info.get("name"),
        id=os_info.get("id"),
        variant_tags=os_info.get("variant_tags", []),
        notes=os_info.get("notes", []),
    )

    tool_findings = [
        ToolFinding(tool=f["tool"], risk=f.get("risk", "unknown"), evidence=f.get("evidence", []))
        for f in classified_findings
    ]

    timeline_events = [
        TimelineEvent(**e) for e in (timeline or [])
    ]

    deleted_findings = [
        DeletedFinding(**d) for d in (deleted or [])
    ]

    persistence_findings = [
        PersistenceFinding(**p) for p in (persistence or [])
    ]

    config_findings = [
        ConfigFinding(**c) for c in (config or [])
    ]

    service_findings = [
        ServiceFinding(**s) for s in (services or [])
    ]

    high_timeline  = sum(1 for e in timeline_events  if e.severity == "high")
    high_deleted   = sum(1 for d in deleted_findings  if d.severity == "high")
    high_persist   = sum(1 for p in persistence_findings if p.severity == "high")
    high_config    = sum(1 for c in config_findings if c.severity in ("high", "critical"))
    high_services  = sum(1 for s in service_findings if s.severity in ("high", "critical"))

    summary = {
        "total_tools":         len(tool_findings),
        "high_risk_tools":     sum(1 for f in tool_findings if f.risk == "high"),
        # keep legacy key so the existing status bar still works
        "high_risk":           sum(1 for f in tool_findings if f.risk == "high"),
        "timeline_events":     len(timeline_events),
        "high_timeline":       high_timeline,
        "deleted_findings":    len(deleted_findings),
        "high_deleted":        high_deleted,
        "persistence_findings": len(persistence_findings),
        "high_persistence":    high_persist,
        "config_findings":     len(config_findings),
        "high_config":         high_config,
        "service_count":       len(service_findings),
        "high_services":       high_services,
        "enabled_services":    sum(1 for s in service_findings if s.state == "enabled"),
        "total_high":          sum(1 for f in tool_findings if f.risk == "high") + high_timeline + high_deleted + high_persist + high_config + high_services,
    }

    return ForensicReport(
        os_info=os_model,
        findings=tool_findings,
        summary=summary,
        timeline=timeline_events,
        deleted=deleted_findings,
        persistence=persistence_findings,
        config=config_findings,
        services=service_findings,
    )
