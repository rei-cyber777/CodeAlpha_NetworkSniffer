"""
CodeAlpha Cyber Security Internship - Task 1
Basic Network Sniffer

Captures live network packets and displays useful information:
source/destination IP, protocol, ports, and a short payload preview.

Requirements:
    pip install scapy

Usage:
    Windows : python sniffer.py            (install Npcap first, run as Administrator)
    Mac/Linux: sudo python3 sniffer.py      (root privileges required to capture packets)

Press Ctrl+C to stop capturing.
"""

from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Where a plain-text log of captured packets is saved for reference.
LOG_FILE = "capture_log.txt"

# Running count of packets seen, so we can show a summary at the end.
packet_count = 0


def get_protocol_name(packet):
    """Return a readable protocol name for a captured packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def get_payload_preview(packet, max_len=40):
    """Return a short, safe preview of the packet's raw payload, if any."""
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        # Replace anything unprintable with a dot so the terminal doesn't break.
        preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes[:max_len])
        return preview
    return ""


def log_line(line):
    """Print a line to the terminal and append it to the log file."""
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def handle_packet(packet):
    """Called automatically by scapy for every packet captured."""
    global packet_count

    # We only care about packets that have an IP layer.
    if not packet.haslayer(IP):
        return

    packet_count += 1
    ip_layer = packet[IP]
    protocol = get_protocol_name(packet)

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    # Ports only exist for TCP/UDP, not ICMP.
    src_port = ""
    dst_port = ""
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    timestamp = datetime.now().strftime("%H:%M:%S")
    payload_preview = get_payload_preview(packet)

    line = f"[{timestamp}] #{packet_count} {protocol:5} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
    if payload_preview:
        line += f"  | payload: {payload_preview}"

    log_line(line)


def main():
    print("Basic Network Sniffer - CodeAlpha Cyber Security Internship")
    print("Capturing packets... press Ctrl+C to stop.\n")

    # Clear the log file at the start of each run.
    open(LOG_FILE, "w").close()

    try:
        # count=0 means "capture until stopped manually".
        sniff(prn=handle_packet, store=False, count=0)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\nCapture stopped. Total packets captured: {packet_count}")
        print(f"Full log saved to: {LOG_FILE}")


if __name__ == "__main__":
    main()
