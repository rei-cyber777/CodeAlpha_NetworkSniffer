# CodeAlpha_NetworkSniffer 

**CodeAlpha Cyber Security Internship — Task 1**

## Overview
A Python-based network sniffer that captures live network traffic and displays useful packet-level information, built as part of the CodeAlpha Cyber Security Internship.

## Contents
- `CodeAlpha_BasicNetworkSniffer.py` — the sniffer script
- `capture_log.txt` — a sample log from a real capture session (1,576 packets)

## Features
- Captures live packets using `scapy`
- Displays protocol (TCP/UDP/ICMP), source/destination IP, source/destination ports
- Shows a readable preview of each packet's payload
- Logs every captured packet to a text file for later review
- Clean shutdown with a packet count summary (Ctrl+C to stop)

## Requirements
```
pip install scapy
```
On Windows, Npcap (installed in WinPcap-compatible mode) is also required.

## Usage
**Windows** (run Command Prompt as Administrator):
```
python CodeAlpha_BasicNetworkSniffer.py
```

**Mac/Linux:**
```
sudo python3 CodeAlpha_BasicNetworkSniffer.py
```

Press `Ctrl+C` to stop capturing. Results are saved to `capture_log.txt`.

## Author
Reindolf Kwame Adusei Appiah
