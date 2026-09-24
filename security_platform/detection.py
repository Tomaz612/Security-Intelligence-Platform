
# Rule to detect deprecated TLS versions (TLS 1.0 and TLS 1.1)
def detect_tls_version(tls_results):
    findings = []

    if "error" in tls_results:
        return findings

    tls_version = tls_results.get("tls_version")

    deprecated_versions = [
        "TLSv1",
        "TLSv1.1"
    ]

    if tls_version in deprecated_versions:
        findings.append({
            "rule_id": "TLS-001",
            "title": "Deprecated TLS Version",
            "severity": "HIGH",
            "description": f"Deprecated TLS version detected: {tls_version}",
            "evidence": tls_version,
            "recommendation": "Disable deprecated TLS versions and require TLS 1.2 or 1.3."
        })

    return findings


# Rule to detect 
def detect_security_headers(http_results):
    findings = []

    for protocol, result in http_results.items():

        if "error" in result:
            continue

        headers = result.get("headers", {})

        security_headers = {
            "Strict-Transport-Security": "HTTP-001",
            "Content-Security-Policy": "HTTP-002",
            "X-Frame-Options": "HTTP-003",
            "X-Content-Type-Options": "HTTP-004",
            "Referrer-Policy": "HTTP-005",
        }

        for header, rule_id in security_headers.items():

            if header not in headers:
                findings.append({
                    "rule_id": rule_id,
                    "title": f"Missing {header}",                    
                    "severity": "LOW",
                    "description": f"{header} header is missing.",
                    "evidence": f"{protocol.upper()} response does not contain {header}",
                    "protocol": protocol.upper(),
                    "recommendation": f"Configure the {header} security header."
                })

    return findings




# Rule to detect exposed services based on open ports
def detect_exposed_services(port_results):
    findings = []

    dangerous_ports = {
        21: {
            "service": "FTP",
            "severity": "MEDIUM"
        },
        23: {
            "service": "Telnet",
            "severity": "HIGH"
        },
        445: {
            "service": "SMB",
            "severity": "MEDIUM"
        },
        3389: {
            "service": "RDP",
            "severity": "MEDIUM"
        }
    }

    for port, status in port_results.items():

        if status != "open":
            continue

        if port in dangerous_ports:

            service = dangerous_ports[port]

            findings.append({
                "rule_id": f"PORT-{port}",
                "title": f"Exposed {service['service']} Service",
                "severity": service["severity"],
                "description": (
                    f"{service['service']} is accessible on TCP port {port}."
                ),
                "evidence": f"TCP/{port} is open",
                "recommendation": (
                    f"Restrict or disable external access to {service['service']} "
                    "if it is not required."
                )
            })

    return findings


# Rule to detect certificate expiration
def detect_certificate(tls_results):
    findings = []

    if "error" in tls_results:
        return findings

    certificate = tls_results.get("certificate")

    if not certificate:
        return findings

    valid_until = certificate.get("valid_until")

    if not valid_until:
        findings.append({
            "rule_id": "TLS-002",
            "title": "Certificate Expiration Date Unavailable",
            "severity": "LOW",
            "description": "The certificate expiration date could not be determined.",
            "evidence": None,
            "recommendation": "Verify the certificate configuration."
        })

    return findings


def run_detections(scan_results):

    findings = []


    findings.extend(
        detect_tls_version(scan_results.get("tls", {}))
    )

    findings.extend(
        detect_certificate(scan_results.get("tls", {}))
    )

    findings.extend(
        detect_security_headers(scan_results.get("http", {}))
    )

    findings.extend(
        detect_exposed_services(scan_results.get("ports", {}))
    )

    return findings