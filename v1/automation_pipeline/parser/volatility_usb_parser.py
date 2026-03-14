"""
DFIR USB Execution Detector
============================
Parses Volatility 3 output files to detect process execution from removable drives.

Detection rule:
    A process is flagged if its command line contains ANY path referencing a
    removable drive - regardless of where the executable itself lives.

    Case 1 - Direct:      E:\\malware.exe
    Case 2 - Interpreter: C:\\Python\\python.exe E:\\script.py
    Case 3 - CMD:         cmd.exe /c E:\\payload.bat
    Case 4 - PowerShell:  powershell.exe -File E:\\evil.ps1

Output: Focused forensic JSON - only flagged processes, no normal process dump.
"""

import os
import re
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("dfir_usb_parser")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SYSTEM_DRIVE_LETTERS = {"C"}

SYSTEM_PATH_PREFIXES = (
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    r"C:\Users",
    r"C:\System",
    r"C:\Recovery",
    r"C:\$Windows.~BT",
    r"C:\$WINDOWS.~WS",
)

# Strict Win32 filesystem path regex.
# Negative lookbehind prevents matching paths preceded by another letter or
# backslash, killing \Device\..., \UMDFCommunicationPorts\..., \\UNC, etc.
# Strict Win32 filesystem path regex.
# Using non-whitespace segment matching ([^\s\\/...]+) instead of [\w\-. ]+
# prevents greedy space consumption that caused "py.exe E" to be matched as
# a single path token - which was breaking Cases 2, 3, and 4.
# The negative lookbehind still kills \Device\..., \UMDFCommunicationPorts\...
PATH_RE = re.compile(
    r'(?<![\\A-Za-z])([A-Za-z]):\\(?:[^\s\\/\[\]"|<>,:;*?]+\\)*[^\s\\/\[\]"|<>,:;*?]*',
    re.IGNORECASE,
)

VOLATILITY_SKIP_PATTERNS = (
    re.compile(r"^Volatility\s+3", re.IGNORECASE),
    re.compile(r"^Progress:"),
    re.compile(r"^\*{3,}"),
    re.compile(r"^-{3,}"),
    re.compile(r"^\s*$"),
)

INTERPRETER_NAMES = (
    "python", "py.exe", "node", "wscript", "cscript",
    "mshta", "ruby", "perl", "java", "javaw",
)

SHELL_NAMES = ("cmd.exe", "powershell.exe", "pwsh.exe")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ProcessRecord:
    pid: int
    ppid: int
    process_name: str
    command_line: str = ""
    create_time: str = ""
    removable_paths_cmdline: list = field(default_factory=list)
    removable_paths_dlls: list = field(default_factory=list)
    removable_paths_handles: list = field(default_factory=list)
    executed_from_removable: bool = False
    evidence_sources: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def is_volatility_header(line: str) -> bool:
    for pat in VOLATILITY_SKIP_PATTERNS:
        if pat.match(line):
            return True
    return False


def extract_paths(text: str) -> list:
    return [m.group(0).rstrip(".,;)\"'") for m in PATH_RE.finditer(text)]


def is_removable_path(path: str) -> bool:
    r"""
    Return True only for real Win32 filesystem paths on non-system drives.

    Rules - ALL must pass:
      1. Must be X:\ format. Rejects \Device\..., \UMDFCommunicationPorts\..., etc.
      2. Drive letter must not be C (system drive).
      3. Must not start with a known system path prefix.
    """
    if not path or len(path) < 3:
        return False
    if not (path[1] == ":" and path[2] == "\\"):
        return False
    if not path[0].isalpha():
        return False
    if path[0].upper() in SYSTEM_DRIVE_LETTERS:
        return False
    path_upper = path.upper()
    for prefix in SYSTEM_PATH_PREFIXES:
        if path_upper.startswith(prefix.upper()):
            return False
    return True


def filter_removable(paths: list) -> list:
    seen = set()
    result = []
    for p in paths:
        if is_removable_path(p) and p not in seen:
            seen.add(p)
            result.append(p)
    return result


# ---------------------------------------------------------------------------
# File reader
# ---------------------------------------------------------------------------

def read_lines(filepath: str) -> list:
    if not os.path.isfile(filepath):
        log.warning("File not found, skipping: %s", filepath)
        return []
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    return [l.rstrip("\n") for l in lines if not is_volatility_header(l)]


# ---------------------------------------------------------------------------
# Artifact parsers
# ---------------------------------------------------------------------------

def parse_pslist(filepath: str) -> dict:
    records = {}
    lines = read_lines(filepath)
    header_found = False
    for line in lines:
        stripped = line.strip()
        if not header_found:
            if re.match(r"PID\s+PPID\s+ImageFileName", stripped, re.IGNORECASE):
                header_found = True
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            name = parts[2]
        except (ValueError, IndexError):
            continue
        create_time = f"{parts[8]} {parts[9]}" if len(parts) >= 10 else ""
        records[pid] = ProcessRecord(pid=pid, ppid=ppid, process_name=name, create_time=create_time)
    log.info("pslist: %d process records", len(records))
    return records


def parse_pstree(filepath: str) -> dict:
    entries = {}
    lines = read_lines(filepath)
    header_found = False
    for line in lines:
        stripped = line.strip()
        if not header_found:
            if re.match(r"PID\s+PPID\s+ImageFileName", stripped, re.IGNORECASE):
                header_found = True
            continue
        clean = re.sub(r"^[*.\s]+", "", stripped)
        parts = clean.split()
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            name = parts[2]
        except (ValueError, IndexError):
            continue
        create_time = f"{parts[8]} {parts[9]}" if len(parts) >= 10 else ""
        entries[pid] = {"pid": pid, "ppid": ppid, "name": name, "create_time": create_time}
    log.info("pstree: %d entries", len(entries))
    return entries


def parse_cmdline(filepath: str) -> dict:
    cmdlines = {}
    lines = read_lines(filepath)
    header_found = False
    for line in lines:
        stripped = line.strip()
        if not header_found:
            if re.match(r"PID\s+Process\s+Args", stripped, re.IGNORECASE):
                header_found = True
            continue
        parts = re.split(r"\s{2,}|\t", stripped, maxsplit=2)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        cmd = parts[2].strip() if len(parts) >= 3 else ""
        if cmd:
            cmdlines[pid] = cmd
    log.info("cmdline: %d command lines", len(cmdlines))
    return cmdlines


def parse_dlllist(filepath: str) -> dict:
    dll_paths = {}
    lines = read_lines(filepath)
    current_pid: Optional[int] = None
    in_dll_block = False
    for line in lines:
        stripped = line.strip()
        pid_header = re.match(r"^(\d+)\s+\S+", stripped)
        if pid_header and not re.match(r"^[0-9a-fA-F]{8,}", stripped):
            try:
                current_pid = int(pid_header.group(1))
                in_dll_block = False
                dll_paths.setdefault(current_pid, [])
            except ValueError:
                pass
            continue
        if re.match(r"Base\s+Size\s+LoadCount", stripped, re.IGNORECASE):
            in_dll_block = True
            continue
        if in_dll_block and current_pid is not None:
            parts = stripped.split()
            if len(parts) >= 4:
                candidate = parts[-1]
                if re.match(r"[A-Za-z]:\\", candidate):
                    dll_paths[current_pid].append(candidate)
    log.info("dlllist: DLL data for %d processes", len(dll_paths))
    return dll_paths


def parse_handles(filepath: str) -> dict:
    handle_paths = {}
    lines = read_lines(filepath)
    header_found = False
    for line in lines:
        stripped = line.strip()
        if not header_found:
            if re.match(r"Offset\s+.*Pid.*Type.*Name", stripped, re.IGNORECASE):
                header_found = True
            continue
        parts = stripped.split()
        if len(parts) < 6:
            continue
        try:
            pid = int(parts[1])
        except (ValueError, IndexError):
            continue
        handle_type = parts[3] if len(parts) > 3 else ""
        name = " ".join(parts[5:]) if len(parts) > 5 else ""
        if handle_type in ("File", "Key", "Directory") and name:
            found = extract_paths(name)
            if found:
                handle_paths.setdefault(pid, [])
                handle_paths[pid].extend(found)
    log.info("handles: handle data for %d processes", len(handle_paths))
    return handle_paths


def parse_malfind(filepath: str) -> set:
    pids = set()
    for line in read_lines(filepath):
        m = re.match(r"^(\d+)\s+\S+\s+0x[0-9a-fA-F]+", line.strip())
        if m:
            try:
                pids.add(int(m.group(1)))
            except ValueError:
                pass
    log.info("malfind: %d suspicious PIDs", len(pids))
    return pids


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def correlate(pslist_records, pstree_entries, cmdlines, dll_paths, handle_paths, malfind_pids):
    r"""
    Merge artefacts and flag processes.

    KEY RULE: scan the ENTIRE command line string for removable paths.
    The executable binary does not need to be on the USB - only a reference
    to a removable-drive path anywhere in the cmdline is enough to flag.

      Direct:      E:\malware.exe
      Interpreter: C:\Python\python.exe E:\script.py   <- E: flagged
      CMD:         cmd.exe /c E:\payload.bat            <- E: flagged
      PowerShell:  powershell.exe -File E:\evil.ps1     <- E: flagged
    """
    for pid, entry in pstree_entries.items():
        if pid not in pslist_records:
            pslist_records[pid] = ProcessRecord(
                pid=pid, ppid=entry["ppid"],
                process_name=entry["name"],
                create_time=entry.get("create_time", ""),
            )
        elif not pslist_records[pid].create_time:
            pslist_records[pid].create_time = entry.get("create_time", "")

    for pid, rec in pslist_records.items():
        cmd = cmdlines.get(pid, "")
        rec.command_line = cmd
        if cmd:
            removable = filter_removable(extract_paths(cmd))
            rec.removable_paths_cmdline = removable
            if removable:
                rec.evidence_sources.append("cmdline")

        removable_dlls = filter_removable(dll_paths.get(pid, []))
        rec.removable_paths_dlls = removable_dlls
        if removable_dlls:
            rec.evidence_sources.append("dlllist")

        removable_handles = filter_removable(handle_paths.get(pid, []))
        rec.removable_paths_handles = removable_handles
        if removable_handles:
            rec.evidence_sources.append("handles")

        if pid in malfind_pids:
            rec.evidence_sources.append("malfind")

        rec.executed_from_removable = bool(
            rec.removable_paths_cmdline
            or rec.removable_paths_dlls
            or rec.removable_paths_handles
        )
        rec.evidence_sources = sorted(set(rec.evidence_sources))

    return pslist_records


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------

# Processes that mark the top of a user-initiated execution chain.
# The chain walk stops once it reaches one of these - they are included
# in the output as the chain root, but their parents are not.
# System boot processes (wininit, services, svchost, smss, System) are
# never included at all.
CHAIN_BOUNDARY_PROCS = {
    "explorer.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
}

# Processes that are pure OS infrastructure - stop and discard if reached.
CHAIN_STOP_PROCS = {
    "system",
    "smss.exe",
    "wininit.exe",
    "services.exe",
    "svchost.exe",
    "lsass.exe",
    "winlogon.exe",
    "userinit.exe",
    "csrss.exe",
}


def build_process_chain(pid: int, records: dict, max_depth: int = 15) -> list:
    """
    Walk PPID chain upward from *pid* and return the user execution chain
    root-first, trimmed of all Windows boot/system processes.

    Walk logic:
      - Collect nodes walking upward via PPID.
      - Stop (and INCLUDE the node) when a CHAIN_BOUNDARY_PROC is reached.
        These are meaningful execution roots (explorer, cmd, powershell).
      - Stop (and EXCLUDE the node and everything above) when a
        CHAIN_STOP_PROC is reached. These are OS infrastructure.
      - Reverse to return root-first order.

    Example result:
        explorer.exe (4748) -> py.exe (1412) -> python.exe (2272)
    """
    chain = []
    visited: set = set()
    current = pid

    while current and current not in visited and len(chain) < max_depth:
        rec = records.get(current)
        if rec is None:
            break

        name_lower = rec.process_name.lower()

        # Hit an OS infrastructure process - discard it and everything above
        if name_lower in CHAIN_STOP_PROCS:
            break

        visited.add(current)
        chain.append({"process": rec.process_name, "pid": rec.pid})

        # Hit a user session boundary - include it but stop climbing
        if name_lower in CHAIN_BOUNDARY_PROCS:
            break

        if rec.ppid == 0 or rec.ppid == current:
            break

        current = rec.ppid

    chain.reverse()
    return chain


def pick_primary_payload(rec: ProcessRecord) -> str:
    """
    Return the most forensically significant removable-drive path.
    Prefers the last cmdline path (the argument/payload, not the interpreter).
    """
    if rec.removable_paths_cmdline:
        return rec.removable_paths_cmdline[-1]
    if rec.removable_paths_dlls:
        return rec.removable_paths_dlls[0]
    if rec.removable_paths_handles:
        return rec.removable_paths_handles[0]
    return ""


def classify_execution(rec: ProcessRecord) -> str:
    cmd_lower = rec.command_line.lower()
    if any(i in cmd_lower for i in INTERPRETER_NAMES) and rec.removable_paths_cmdline:
        return "Interpreter Execution"
    if any(s in cmd_lower for s in SHELL_NAMES) and rec.removable_paths_cmdline:
        return "Shell Execution"
    if rec.removable_paths_cmdline:
        first = rec.removable_paths_cmdline[0]
        if cmd_lower.startswith(first[0].lower() + ":\\"):
            return "Direct Execution"
        return "Command Line Reference"
    return "Indirect Reference"


# ---------------------------------------------------------------------------
# Event merging and report builder
# ---------------------------------------------------------------------------

def merge_execution_events(flagged: list, records: dict) -> list:
    r"""
    Merge flagged processes that reference the same removable payload into a
    single execution event.

    Why this is needed:
        When python.exe is launched via py.exe, both processes appear in
        cmdline with the same E:\script.py argument. Without merging, the
        report emits two events for what is a single user action.

    Merge algorithm:
        1. Group flagged records by their primary payload path (normalised
           to uppercase so drive-letter case differences don't matter).
        2. Within each group, find the deepest child process - the one whose
           PID does not appear as the PPID of any other process in the group.
           That process represents the final execution stage.
        3. Build the process chain from that deepest process upward; the chain
           naturally includes all intermediate interpreter/launcher nodes.
        4. Use the earliest creation time in the group as the event time
           (that is when the user action began).

    Returns a list of merged event dicts, sorted by execution_time.
    """
    # Index PIDs in the flagged set for fast lookup
    flagged_pids = {r.pid for r in flagged}

    # Group by normalised payload path
    groups: dict = {}
    for rec in flagged:
        payload = pick_primary_payload(rec)
        key = payload.upper()
        groups.setdefault(key, []).append(rec)

    events = []
    for payload_key, group in groups.items():
        # Find the deepest process: its PID is not the PPID of any sibling
        ppids_in_group = {r.ppid for r in group}
        deepest = None
        for rec in group:
            if rec.pid not in ppids_in_group:
                # Not a parent of anyone else in the group - it's the leaf
                if deepest is None or rec.create_time > (deepest.create_time or ""):
                    deepest = rec

        # Fallback: if all are parents of each other (unusual), take last by time
        if deepest is None:
            deepest = max(group, key=lambda r: r.create_time or "")

        payload = pick_primary_payload(deepest)
        drive = payload[:2].upper() if payload else ""
        chain = build_process_chain(deepest.pid, records)

        # Earliest time in the group = when the user action started
        earliest_time = min(
            (r.create_time for r in group if r.create_time),
            default=deepest.create_time,
        )

        evidence_src = (
            "Command Line Artifact"
            if any("cmdline" in r.evidence_sources for r in group)
            else ", ".join(sorted({s for r in group for s in r.evidence_sources}))
        )

        events.append({
            "removable_drive": drive,
            "executed_payload": payload,
            "execution_time": earliest_time,
            "process_chain": chain,
            "evidence_source": evidence_src,
        })

    events.sort(key=lambda e: e["execution_time"] or "")
    return events


def build_report(records: dict) -> dict:
    """
    Focused forensic investigation report.

    - Only flagged processes feed into events.
    - Events sharing the same payload are merged into one.
    - Normal Windows processes are completely absent from output.
    """
    drives = set()
    for rec in records.values():
        for p in rec.removable_paths_cmdline + rec.removable_paths_dlls + rec.removable_paths_handles:
            drives.add(p[:2].upper())

    removable_drives = sorted(drives)
    flagged = sorted(
        [r for r in records.values() if r.executed_from_removable],
        key=lambda r: r.create_time or "",
    )

    execution_events = merge_execution_events(flagged, records)

    return {
        "summary": {
            "usb_execution_detected": len(execution_events) > 0,
            "removable_drives_detected": removable_drives,
            "execution_events": len(execution_events),
        },
        "execution_events": execution_events,
    }


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_parser(input_dir: str, output_path: str) -> None:
    def p(name):
        return os.path.join(input_dir, name)

    log.info("=== DFIR USB Execution Detector ===")
    log.info("Input : %s", input_dir)
    log.info("Output: %s", output_path)

    pslist_records = parse_pslist(p("pslist.txt"))
    pstree_entries = parse_pstree(p("pstree.txt"))
    cmdlines       = parse_cmdline(p("cmdline.txt"))
    dll_paths      = parse_dlllist(p("dlllist.txt"))
    handle_paths   = parse_handles(p("handles.txt"))
    malfind_pids   = parse_malfind(p("malfind.txt"))

    log.info("Correlating artefacts...")
    records = correlate(pslist_records, pstree_entries, cmdlines, dll_paths, handle_paths, malfind_pids)

    report = build_report(records)
    log.info("Flagged : %d events", report["summary"]["execution_events"])
    log.info("Drives  : %s", report["summary"]["removable_drives_detected"] or "none")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    log.info("Report written: %s", output_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="DFIR USB Execution Detector - Volatility 3 output parser"
    )
    ap.add_argument(
        "--input-dir",
        default=os.path.join("forensic_validation", "volatility_outputs"),
        help="Directory containing Volatility .txt output files",
    )
    ap.add_argument(
        "--output",
        default="usb_execution_report.json",
        help="Path for the JSON report (default: usb_execution_report.json)",
    )
    args = ap.parse_args()
    run_parser(input_dir=args.input_dir, output_path=args.output)