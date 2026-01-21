# USBTrace-DFIR
Automated digital forensics pipeline for analyzing USB-based infection scenarios using memory and log correlation.

## Project Goal
USBTrace-DFIR aims to automate digital forensics analysis of USB-based infection scenarios by correlating memory artifacts and system logs to reconstruct the infection chain, identify malicious processes, and generate a structured forensic report.

The project focuses on understanding **when, where, how, and which process** was involved in a USB-triggered compromise within a sandboxed environment.

---

## Scope (Version 1)
- Windows-based sandboxed analysis environment
- Memory acquisition and analysis (processes, parent-child relations)
- Windows event log and Sysmon log parsing
- Correlation of memory artifacts with system logs
- Timeline reconstruction of USB-triggered activity
- Machine-readable forensic output (JSON/CSV)

---

## Status
Project initialization and DFIR pipeline design phase.
