"""AI-based timeline analysis and attack reconstruction."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from .agent_core import get_agent, _gemini_chat, _SYSTEM as AGENT_SYSTEM, _parse_json

logger = logging.getLogger(__name__)

TIMELINE_AI_SYSTEM = """
You are an expert forensic analyst. You are given a list of timeline events from a system under investigation.
Your task is to:
1. Identify the "Probable Attack Sequence": Group related events into logical attack phases (e.g., Initial Access, Reconnaissance, Persistence, Exfiltration).
2. Provide "AI Insights": Synthesize what these events mean collectively. Highlight suspicious patterns that might not be obvious from individual events.
3. "Predict the Attack": Based on the observed TTPs (Tactics, Techniques, and Procedures), predict what the attacker's ultimate goal likely was, or what their next steps would have been if they weren't stopped.

Respond ONLY with a JSON object in the following format:
{
  "attack_sequence": [
    {
      "phase": "Phase Name",
      "description": "Brief description of what happened in this phase",
      "event_indices": [0, 1, 2],
      "severity": "info|medium|high|critical"
    }
  ],
  "insights": "General forensic insights about the timeline...",
  "attack_prediction": {
    "likely_goal": "What the attacker wanted",
    "next_steps": ["Step 1", "Step 2"],
    "confidence": "low|medium|high"
  }
}

If no suspicious activity is found, state that the system appears clean but still provided a logical summary of the identified events.
"""

def analyze_timeline_ai(events: List[Dict]) -> Dict:
    """Send timeline events to Gemini for attack reconstruction and prediction."""
    agent = get_agent()
    client = agent._get_client()
    
    # Truncate events if there are too many to fit in context efficiently, 
    # but for timeline, we usually want at least the high-severity ones.
    # We'll send a summary version of events to save tokens.
    summarized_events = []
    for i, ev in enumerate(events):
        summarized_events.append({
            "index": i,
            "ts": ev.get("timestamp"),
            "source": ev.get("source"),
            "type": ev.get("event_type"),
            "detail": ev.get("detail"),
            "severity": ev.get("severity")
        })

    prompt = f"Analyze the following {len(events)} timeline events:\n\n{json.dumps(summarized_events, indent=2)}\n\nProvide the attack sequence, insights, and prediction."
    
    # We use a history that establishes the role
    history = [{"role": "user", "parts": [prompt]}]
    
    try:
        raw_response = _gemini_chat(history, TIMELINE_AI_SYSTEM, client)
        return _parse_json(raw_response)
    except Exception as e:
        logger.error(f"Timeline AI analysis failed: {e}")
        return {
            "error": f"AI analysis failed: {str(e)}",
            "attack_sequence": [],
            "insights": "Analysis unavailable.",
            "attack_prediction": {"likely_goal": "Unknown", "next_steps": [], "confidence": "none"}
        }
