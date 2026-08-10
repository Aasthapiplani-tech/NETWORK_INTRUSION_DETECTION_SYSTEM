"""
Detection rules for the NIDS. Each rule is a small, independent function that
takes a parsed packet, the TrafficAnalyzer, and config thresholds, and
returns an alert dict if the rule is triggered, or None otherwise.
"""


def check_port_scan(parsed_packet, analyzer, config):
    """
    FR-04: Flags a source IP that has contacted more unique destination
    ports than the configured threshold within the time window.
    """
    if not parsed_packet.src_ip or parsed_packet.dst_port is None:
        return None

    threshold = config.get("detection", "port_scan", "unique_ports_threshold")
    window = config.get("detection", "port_scan", "time_window_seconds")

    unique_ports = analyzer.get_unique_ports(parsed_packet.src_ip, window)

    if unique_ports > threshold:
        return {
            "type": "PORT_SCAN",
            "severity": "HIGH",
            "src_ip": parsed_packet.src_ip,
            "description": (
                f"{parsed_packet.src_ip} contacted {unique_ports} unique ports "
                f"in {window}s (threshold: {threshold})"
            ),
        }
    return None


def check_syn_flood(parsed_packet, analyzer, config):
    """
    FR-05: Flags a source IP sending more unmatched SYN packets than the
    configured threshold within the time window.
    """
    if not parsed_packet.src_ip or parsed_packet.protocol != "TCP":
        return None

    threshold = config.get("detection", "syn_flood", "syn_count_threshold")
    window = config.get("detection", "syn_flood", "time_window_seconds")

    syn_count = analyzer.get_syn_count(parsed_packet.src_ip, window)

    if syn_count > threshold:
        return {
            "type": "SYN_FLOOD",
            "severity": "CRITICAL",
            "src_ip": parsed_packet.src_ip,
            "description": (
                f"{parsed_packet.src_ip} sent {syn_count} unmatched SYN packets "
                f"in {window}s (threshold: {threshold})"
            ),
        }
    return None


def check_icmp_flood(parsed_packet, analyzer, config):
    """
    FR-06: Flags a source IP sending more ICMP packets than the configured
    threshold within the time window.
    """
    if not parsed_packet.src_ip or parsed_packet.protocol != "ICMP":
        return None

    threshold = config.get("detection", "icmp_flood", "icmp_count_threshold")
    window = config.get("detection", "icmp_flood", "time_window_seconds")

    icmp_count = analyzer.get_icmp_count(parsed_packet.src_ip, window)

    if icmp_count > threshold:
        return {
            "type": "ICMP_FLOOD",
            "severity": "MEDIUM",
            "src_ip": parsed_packet.src_ip,
            "description": (
                f"{parsed_packet.src_ip} sent {icmp_count} ICMP packets "
                f"in {window}s (threshold: {threshold})"
            ),
        }
    return None


def check_dns_tunneling(parsed_packet, analyzer, config):
    """
    FR-07: Flags DNS queries with abnormally long subdomains, a common
    indicator of DNS tunneling (data smuggled inside DNS queries).
    """
    if not parsed_packet.dns_query:
        return None

    threshold = config.get("detection", "dns_tunneling", "subdomain_length_threshold")
    query = parsed_packet.dns_query.rstrip(".")
    labels = query.split(".")

    if labels and len(labels[0]) > threshold:
        return {
            "type": "DNS_TUNNELING",
            "severity": "MEDIUM",
            "src_ip": parsed_packet.src_ip,
            "description": (
                f"Suspiciously long DNS subdomain ({len(labels[0])} chars, "
                f"threshold: {threshold}): {query[:80]}..."
            ),
        }
    return None


def check_malicious_ip(parsed_packet, analyzer, config):
    """
    FR-08: Flags any packet involving a known malicious IP address.
    """
    malicious_ips = set(config.get("detection", "malicious_ips", default=[]))
    if not malicious_ips:
        return None

    if parsed_packet.src_ip in malicious_ips or parsed_packet.dst_ip in malicious_ips:
        flagged_ip = (
            parsed_packet.src_ip if parsed_packet.src_ip in malicious_ips else parsed_packet.dst_ip
        )
        return {
            "type": "MALICIOUS_IP",
            "severity": "CRITICAL",
            "src_ip": parsed_packet.src_ip,
            "description": f"Traffic involving known malicious IP: {flagged_ip}",
        }
    return None


def check_malicious_port(parsed_packet, analyzer, config):
    """
    FR-08: Flags any packet involving a known malicious port.
    """
    malicious_ports = set(config.get("detection", "malicious_ports", default=[]))
    if not malicious_ports:
        return None

    ports_used = {parsed_packet.src_port, parsed_packet.dst_port} - {None}
    hit = ports_used & malicious_ports

    if hit:
        return {
            "type": "MALICIOUS_PORT",
            "severity": "HIGH",
            "src_ip": parsed_packet.src_ip,
            "description": f"Traffic on known malicious port(s): {hit}",
        }
    return None


# Registry of all active rules — the DetectionEngine iterates over this list.
ALL_RULES = [
    check_port_scan,
    check_syn_flood,
    check_icmp_flood,
    check_dns_tunneling,
    check_malicious_ip,
    check_malicious_port,
]