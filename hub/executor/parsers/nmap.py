"""Parse nmap output → entities.

Supports nmap XML output (-oX -) and grepable output (-oG -).
Extracts: open ports → service entities with port/protocol metadata.
"""
import re
import xml.etree.ElementTree as ET


def parse(raw_output: str, target: str = "") -> list[dict]:
    """Parse nmap scan output into structured entities.

    Tries XML parsing first, falls back to grepable format.
    Returns list of {type, value, confidence, sources, metadata} dicts.
    """
    entities = []

    # Try XML output first (-oX -)
    if raw_output.strip().startswith("<?xml") or "<nmaprun" in raw_output:
        try:
            root = ET.fromstring(raw_output)
            for host in root.findall(".//host"):
                host_ip = None
                for addr in host.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        host_ip = addr.get("addr")
                        # Add IP entity
                        entities.append({
                            "type": "ip",
                            "value": host_ip,
                            "confidence": 0.95,
                            "sources": [f"nmap:{target}"],
                            "source": "tool_output",
                            "metadata": {"discovery": "nmap_scan"},
                        })

                for port in host.findall(".//port"):
                    if port.find("state").get("state") == "open":
                        port_num = port.get("portid")
                        protocol = port.get("protocol")
                        service = port.find("service")
                        service_name = service.get("name", "unknown") if service is not None else "unknown"

                        entities.append({
                            "type": "service",
                            "value": f"{service_name}:{port_num}/{protocol}",
                            "confidence": 0.90,
                            "sources": [f"nmap:{host_ip or target}"],
                            "source": "tool_output",
                            "metadata": {
                                "port": int(port_num),
                                "protocol": protocol,
                                "service_name": service_name,
                                "host": host_ip or target,
                            },
                        })
        except ET.ParseError:
            pass  # Fall through to grepable parsing

    # Try grepable output (-oG -)
    if not entities:
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if line.startswith("#") or "Ports:" not in line:
                continue

            # Extract host IP
            host_match = re.search(r'Host:\s+(\S+)', line)
            host_ip = host_match.group(1) if host_match else target

            # Extract ports section
            ports_match = re.search(r'Ports:\s+(.+)', line)
            if not ports_match:
                continue

            ports_str = ports_match.group(1)
            for port_entry in ports_str.split(","):
                port_entry = port_entry.strip()
                # Format: "22/open/tcp//ssh//"
                m = re.match(r'(\d+)/open/(\w+)//(\w*)//', port_entry)
                if m:
                    port_num = m.group(1)
                    protocol = m.group(2)
                    service_name = m.group(3) or "unknown"

                    entities.append({
                        "type": "service",
                        "value": f"{service_name}:{port_num}/{protocol}",
                        "confidence": 0.90,
                        "sources": [f"nmap:{host_ip}"],
                        "source": "tool_output",
                        "metadata": {
                            "port": int(port_num),
                            "protocol": protocol,
                            "service_name": service_name,
                            "host": host_ip,
                        },
                    })

    return entities
