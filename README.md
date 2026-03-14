# USBTrace-DFIR

USBTrace-DFIR is an automated digital forensics pipeline designed to analyze **USB-based infection scenarios** by correlating **memory artifacts and Windows system logs**.

## Project Goal

The goal of this project is to reconstruct the **execution chain of a USB-triggered compromise** and determine:

* When the activity occurred
* Where the execution originated
* How the process chain evolved
* Which processes were involved

The system extracts relevant forensic artifacts and generates a **structured investigation output**.

## Scope (Version 1)

Version 1 focuses on **memory-based live response analysis** in a Windows sandbox environment.

Main components include:

* Memory acquisition from a running system
* Process and parent–child relationship analysis
* Windows Event Log parsing
* Sysmon log parsing
* Correlation of memory artifacts with system logs
* Timeline reconstruction of USB-triggered activity
* Machine-readable forensic output (JSON / CSV)

## Status

Early development phase – DFIR pipeline design and testing.
