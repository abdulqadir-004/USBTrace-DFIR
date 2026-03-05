# USB Behavior Simulator

## Purpose

The **USB Behavior Simulator** is a small controlled program designed to generate predictable forensic artifacts for testing the **USBTrace-DFIR** analysis pipeline.

It simulates activity commonly observed during suspicious USB-based execution so that the DFIR pipeline can be validated in a controlled lab environment.

This tool **does not perform any malicious actions**. It only creates benign artifacts that can be detected and reconstructed during forensic analysis.

## Why This Exists

When developing DFIR automation, testing against real malware is unreliable and unsafe.
This simulator provides **deterministic behavior** so that investigators can verify whether memory forensics tools correctly detect and reconstruct execution activity.

It allows validation of:

* Process execution chains
* Parent–child relationships
* Loaded modules
* System handles
* Registry modifications
* File system activity

These artifacts can later be extracted using memory forensic frameworks such as Volatility.

## Artifacts Generated

When executed, the simulator intentionally creates the following artifacts:

* File creation activity
* Registry key creation
* Mutex object creation
* DLL loading
* Command execution via system shell

These actions produce observable traces in memory that can be analyzed during DFIR investigations.

## Usage

1. Place the script on a removable drive (USB).
2. Execute the script directly from the USB device.
3. Capture a memory snapshot while the program is running.
4. Analyze the memory image using forensic tools.

Example execution:

```
python usb_behavior_simulator.py
```

## Role in USBTrace-DFIR

This simulator is used during the **testing phase** of the USBTrace-DFIR project to validate that the pipeline can:

* Detect execution originating from removable media
* Identify process relationships
* Extract behavioral artifacts from memory
* Reconstruct the activity timeline
