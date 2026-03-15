"""
USBTrace-DFIR — Timeline Reconstruction Engine
================================================
Module  : timeline_builder.py
Location: USBTrace-DFIR/v1/automation_pipeline/timeline/timeline_builder.py

Reads usb_execution_report.json produced by volatility_usb_parser.py and converts
execution events into a chronological attack timeline.

This module does NOT touch parser logic. It is read-only with respect to
parsed_artifacts.json and writes two output files:
    - timeline_report.json        (machine-readable)
    - timeline_report.txt         (human-readable investigator report)

Usage:
    python3 timeline_builder.py --input parsed_artifacts.json
    python3 timeline_builder.py --input parsed_artifacts.json --output-dir ./reports
"""

import os
import json
import logging
import argparse
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("timeline_builder")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# When a process chain has more than one node, we space out the launch events
# by this many seconds so the timeline is readable and ordered. Real memory
# forensics rarely has sub-second precision in Volatility pslist timestamps,
# so this synthetic delta is clearly artificial but intentional.
LAUNCH_EVENT_DELTA_SECONDS = 1

REPORT_SEPARATOR = "=" * 55
REPORT_HEADER    = "USB EXECUTION TIMELINE"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_artifacts(filepath: str) -> dict:
    """
    Load and validate usb_execution_report.json.

    Raises:
        FileNotFoundError : if the file does not exist.
        ValueError        : if the file is not valid JSON or missing keys.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Artifacts file not found: {filepath}")

    with open(filepath, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {filepath}: {exc}") from exc

    if "execution_events" not in data:
        raise ValueError(
            f"'execution_events' key missing from {filepath}. "
            "Is this a valid usb_execution_report.json file?"
        )

    return data


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def parse_timestamp(raw: str) -> datetime | None:
    """
    Parse a timestamp string into a datetime object.

    Accepts common Volatility/Python formats:
        "2026-03-05 13:56:19"
        "2026-03-05 13:56:19.000000"
        "2026-03-05T13:56:19"
    Returns None if parsing fails so callers can handle gracefully.
    """
    if not raw:
        return None

    formats = (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    )
    for fmt in formats:
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    log.warning("Could not parse timestamp: %r", raw)
    return None


def format_timestamp(dt: datetime) -> str:
    """Return a clean display string: '2026-03-05 13:56:19'."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def format_time_only(dt: datetime) -> str:
    """Return time-only display string: '13:56:19'."""
    return dt.strftime("%H:%M:%S")


# ---------------------------------------------------------------------------
# Core timeline builder
# ---------------------------------------------------------------------------

def build_timeline_for_event(event: dict, event_index: int) -> list[dict]:
    """
    Convert a single execution event into an ordered list of timeline entries.

    Timeline construction rules:
      1. Each consecutive pair in the process chain produces a "X launched Y"
         entry, timestamped at base_time + (step * LAUNCH_EVENT_DELTA_SECONDS).
      2. The final entry is always "final_process executed <payload>", stamped
         at the same time as the last launch entry.
      3. If the chain has only one process, that process gets the execution
         entry directly — no launch entry is emitted.
      4. PIDs are taken from the chain. The launch entry for "A launched B"
         carries B's PID (B is the process being created).

    Returns a list of timeline entry dicts:
        {
            "time": "2026-03-05 13:56:19",
            "event": "explorer.exe launched py.exe",
            "pid": 1412,
            "event_index": 0,        # which execution_event this came from
        }
    """
    chain   = event.get("process_chain", [])
    payload = event.get("executed_payload", "")
    raw_ts  = event.get("execution_time", "")

    if not chain:
        log.warning("Event %d has an empty process_chain — skipping.", event_index)
        return []

    base_time = parse_timestamp(raw_ts)

    entries = []
    seen_events: set[str] = set()   # deduplication within this event

    def add_entry(dt: datetime | None, description: str, pid: int) -> None:
        if description in seen_events:
            return
        seen_events.add(description)
        time_str = format_timestamp(dt) if dt else raw_ts or "UNKNOWN"
        entries.append({
            "time": time_str,
            "event": description,
            "pid": pid,
            "event_index": event_index,
        })

    # ── Generate "parent launched child" entries for each chain step ─────────
    for step, node in enumerate(chain[:-1]):
        parent_name = node.get("process", "unknown")
        child       = chain[step + 1]
        child_name  = child.get("process", "unknown")
        child_pid   = child.get("pid", 0)

        # Offset each launch event by delta so ordering is unambiguous
        if base_time:
            entry_time = base_time + timedelta(seconds=step * LAUNCH_EVENT_DELTA_SECONDS)
        else:
            entry_time = None

        add_entry(entry_time, f"{parent_name} launched {child_name}", child_pid)

    # ── Final execution entry: last process in chain executed the payload ─────
    final_proc = chain[-1]
    final_name = final_proc.get("process", "unknown")
    final_pid  = final_proc.get("pid", 0)

    if base_time:
        # Stamp the execution entry at the same offset as the last launch step
        last_step  = max(len(chain) - 2, 0)
        final_time = base_time + timedelta(seconds=last_step * LAUNCH_EVENT_DELTA_SECONDS)
    else:
        final_time = None

    payload_label = payload if payload else "unknown payload"
    add_entry(final_time, f"{final_name} executed {payload_label}", final_pid)

    return entries


def build_timeline(artifacts: dict) -> list[dict]:
    """
    Process all execution events and return a merged, deduplicated,
    chronologically sorted timeline.

    Each returned entry has:
        time         — display timestamp string
        event        — human-readable description
        pid          — PID of the process being created or executing
        event_index  — index into execution_events (for traceability)
    """
    execution_events = artifacts.get("execution_events", [])

    if not execution_events:
        log.warning("No execution events found in artifacts.")
        return []

    all_entries = []
    global_seen: set[str] = set()   # cross-event deduplication key

    for idx, ev in enumerate(execution_events):
        entries = build_timeline_for_event(ev, event_index=idx)
        for entry in entries:
            # Dedup key: time + event description
            dedup_key = f"{entry['time']}|{entry['event']}"
            if dedup_key not in global_seen:
                global_seen.add(dedup_key)
                all_entries.append(entry)

    # Sort by time string (ISO format sorts lexicographically) then by
    # event_index as a tiebreaker to keep intra-event order stable
    all_entries.sort(key=lambda e: (e["time"], e["event_index"]))

    log.info("Timeline built: %d entries from %d event(s)",
             len(all_entries), len(execution_events))
    return all_entries


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def build_json_report(artifacts: dict, timeline: list[dict]) -> dict:
    """
    Build the machine-readable JSON report.

    The event_index field is internal scaffolding — strip it from the
    public-facing output so the schema stays clean.
    """
    summary = artifacts.get("summary", {})

    clean_entries = [
        {
            "time":  e["time"],
            "event": e["event"],
            "pid":   e["pid"],
        }
        for e in timeline
    ]

    return {
        "summary": {
            "usb_execution_detected":   summary.get("usb_execution_detected", False),
            "removable_drives_detected": summary.get("removable_drives_detected", []),
            "execution_events":          summary.get("execution_events", 0),
            "timeline_entries":          len(clean_entries),
        },
        "timeline": clean_entries,
    }


def build_text_report(artifacts: dict, timeline: list[dict]) -> str:
    """
    Build the human-readable investigator report.

    Groups timeline entries by execution event so the report is easy to
    follow when multiple USB payloads were detected.
    """
    lines = []
    summary = artifacts.get("summary", {})
    execution_events = artifacts.get("execution_events", [])

    lines.append(REPORT_SEPARATOR)
    lines.append(REPORT_HEADER)
    lines.append(REPORT_SEPARATOR)
    lines.append("")

    # Summary block
    detected = summary.get("usb_execution_detected", False)
    drives   = summary.get("removable_drives_detected", [])
    n_events = summary.get("execution_events", 0)

    lines.append(f"  USB Execution Detected : {'YES' if detected else 'NO'}")
    lines.append(f"  Removable Drives       : {', '.join(drives) if drives else 'None'}")
    lines.append(f"  Execution Events       : {n_events}")
    lines.append("")

    if not timeline:
        lines.append("  No timeline entries to display.")
        lines.append("")
        lines.append(REPORT_SEPARATOR)
        return "\n".join(lines)

    # Group entries by event_index for per-event sections
    groups: dict[int, list[dict]] = {}
    for entry in timeline:
        idx = entry.get("event_index", 0)
        groups.setdefault(idx, []).append(entry)

    for idx, group_entries in sorted(groups.items()):
        # Retrieve the source event for section header details
        source_event = execution_events[idx] if idx < len(execution_events) else {}
        drive   = source_event.get("removable_drive", "?")
        payload = source_event.get("executed_payload", "?")

        lines.append(f"  [ Event {idx + 1} ]  Drive: {drive}   Payload: {payload}")
        lines.append("")

        for entry in group_entries:
            # Time-only for compact display; full datetime already in JSON
            raw_time = entry["time"]
            dt = parse_timestamp(raw_time)
            display_time = format_time_only(dt) if dt else raw_time
            lines.append(f"    {display_time}   {entry['event']}")

        lines.append("")

    lines.append(REPORT_SEPARATOR)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def write_json(data: dict, filepath: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    log.info("JSON report written : %s", filepath)


def write_text(content: str, filepath: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(content)
        fh.write("\n")
    log.info("Text report written : %s", filepath)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run(input_path: str, output_dir: str) -> None:
    """
    Full pipeline:
        load artifacts → build timeline → write JSON + text reports.
    """
    log.info("=== USBTrace-DFIR Timeline Builder ===")
    log.info("Input  : %s", input_path)
    log.info("Output : %s", output_dir)

    # 1. Load
    artifacts = load_artifacts(input_path)
    n = len(artifacts.get("execution_events", []))
    log.info("Loaded %d execution event(s)", n)

    # 2. Build timeline
    timeline = build_timeline(artifacts)

    # 3. Build reports
    json_report = build_json_report(artifacts, timeline)
    text_report = build_text_report(artifacts, timeline)

    # 4. Write outputs
    json_path = os.path.join(output_dir, "usb_execution_report.json")
    text_path = os.path.join(output_dir, "timeline_report.txt")
    write_json(json_report, json_path)
    write_text(text_report, text_path)

    # 5. Print text report to stdout for immediate visibility
    print()
    print(text_report)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="USBTrace-DFIR Timeline Builder — converts parsed_artifacts.json "
                    "into a chronological attack timeline."
    )
    ap.add_argument(
        "--input",
        default="usb_execution_report.json",
        help="Path to usb_execution_report.json (default: usb_execution_report.json)",
    )
    ap.add_argument(
        "--output-dir",
        default=".",
        help="Directory for output reports (default: current directory)",
    )
    args = ap.parse_args()
    run(input_path=args.input, output_dir=args.output_dir)