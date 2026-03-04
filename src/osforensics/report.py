"""Reporting models and helpers to build structured forensic output.
"""
from __future__ import annotations

from typing import List, Dict, Any
from pydantic import BaseModel


class ToolFinding(BaseModel):
    tool: str
    risk: str
    evidence: List[str]


class OSInfo(BaseModel):
    name: str | None = None
    id: str | None = None
    variant_tags: List[str] = []
    notes: List[str] = []


class ForensicReport(BaseModel):
    os_info: OSInfo
    findings: List[ToolFinding]
    summary: Dict[str, Any] = {}


def build_report(os_info: Dict[str, object], classified_findings: List[Dict[str, object]]) -> ForensicReport:
    os_model = OSInfo(
        name=os_info.get("name"),
        id=os_info.get("id"),
        variant_tags=os_info.get("variant_tags", []),
        notes=os_info.get("notes", []),
    )

    findings = [ToolFinding(tool=f["tool"], risk=f.get("risk", "unknown"), evidence=f.get("evidence", [])) for f in classified_findings]

    summary = {
        "total_tools": len(findings),
        "high_risk": sum(1 for f in findings if f.risk == "high"),
    }

    return ForensicReport(os_info=os_model, findings=findings, summary=summary)
