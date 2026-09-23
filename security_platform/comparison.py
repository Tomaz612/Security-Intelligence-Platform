def compare_scans(previous_scan, current_scan):

    comparison = {}

    risk_changes = compare_risk(previous_scan, current_scan)

    if risk_changes:
        comparison["risk"] = risk_changes

    previous_ports = previous_scan["scan_results"].get("ports", {})
    current_ports = current_scan["scan_results"].get("ports", {})

    port_changes = compare_ports(previous_ports, current_ports)

    if port_changes["opened"] or port_changes["closed"]:
        comparison["ports"] = port_changes

    previous_dns = previous_scan["scan_results"].get("dns", {})
    current_dns = current_scan["scan_results"].get("dns", {})

    dns_changes = compare_dns(previous_dns, current_dns)

    if dns_changes:
        comparison["dns"] = dns_changes

    return comparison



def compare_risk(previous_scan, current_scan):

    changes = {}

    previous_score = previous_scan["risk_score"]
    current_score = current_scan["risk_score"]

    if previous_score != current_score:
        changes["risk_score"] = {
            "previous": previous_score,
            "current": current_score
        }

    previous_level = previous_scan["risk_level"]
    current_level = current_scan["risk_level"]

    if previous_level != current_level:
        changes["risk_level"] = {
            "previous": previous_level,
            "current": current_level
        }

    return changes



def compare_ports(previous_ports, current_ports):
    changes = {
        "opened": [],
        "closed": []
    }

    # Normalize port keys to integers
    previous_ports = {
        int(port): status
        for port, status in previous_ports.items()
    }

    current_ports = {
        int(port): status
        for port, status in current_ports.items()
    }

    all_ports = set(previous_ports) | set(current_ports)

    for port in all_ports:
        previous_status = previous_ports.get(port)
        current_status = current_ports.get(port)

        if previous_status != "open" and current_status == "open":
            changes["opened"].append(port)

        elif previous_status == "open" and current_status != "open":
            changes["closed"].append(port)

    return changes



def compare_dns(previous_dns, current_dns):

    changes = {}

    previous_ipv4 = set(previous_dns.get("ipv4", []))
    current_ipv4 = set(current_dns.get("ipv4", []))

    added_ipv4 = current_ipv4 - previous_ipv4
    removed_ipv4 = previous_ipv4 - current_ipv4

    if added_ipv4 or removed_ipv4:
        changes["ipv4"] = {
            "added": list(added_ipv4),
            "removed": list(removed_ipv4)
        }

    previous_ipv6 = set(previous_dns.get("ipv6", []))
    current_ipv6 = set(current_dns.get("ipv6", []))

    added_ipv6 = current_ipv6 - previous_ipv6
    removed_ipv6 = previous_ipv6 - current_ipv6

    if added_ipv6 or removed_ipv6:
        changes["ipv6"] = {
            "added": list(added_ipv6),
            "removed": list(removed_ipv6)
        }

    return changes