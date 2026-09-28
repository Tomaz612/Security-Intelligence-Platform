import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security_platform.detection import run_detections

def test_deprecated_tls_detection():
    scan_results = {
        "tls": {
            "tls_version": "TLSv1"
        }
    }

    findings = run_detections(scan_results)

    assert any(
        finding["severity"] == "HIGH"
        for finding in findings
    )


def test_missing_security_header():
    scan_results = {
        "http": {
            "security_headers": {
                "strict_transport_security": False
            }
        }
    }

    findings = run_detections(scan_results)

    print(findings)  # Debugging line to print findings

    assert any(
        finding["rule_id"] == "HTTP-001"
        for finding in findings
    )