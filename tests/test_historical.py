import sys
from pathlib import Path
from unittest import result

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security_platform.comparison import compare_scans

def test_no_changes():
    previous = {
        "risk_score": 20,
        "risk_level": "MODERATE",
        "scan_results": {
            "ports": {
                "22": "closed",
                "443": "open"
            },
            "dns": {
                "ipv4": ["1.2.3.4"],
                "ipv6": ["::1"]
            }
        }
    }

    current = {
        "risk_score": 20,
        "risk_level": "MODERATE",
        "scan_results": {
            "ports": {
                "22": "closed",
                "443": "open"
            },
            "dns": {
                "ipv4": ["1.2.3.4"],
                "ipv6": ["::1"]
            }
        }
    }

    result = compare_scans(previous, current)

    assert result == {}


def test_port_opened():

    previous = {
        "risk_score": 20,
        "risk_level": "MODERATE",
        "scan_results": {
            "ports": {
                "22": "closed"
            }
        }
    }

    current = {
        "risk_score": 20,
        "risk_level": "MODERATE",
        "scan_results": {
            "ports": {
                "22": "open"
            }
        }
    }

    result = compare_scans(previous, current)

    assert "ports" in result
    assert 22 in result["ports"]["opened"]



def test_ipv4_added():

    previous = {
        "risk_score": 20,
        "risk_level": "MODERATE",
        "scan_results": {
            "dns": {
                "ipv4": ["1.2.3.4"]
            }
        }
    }

    current = {
        "risk_score": 20,
        "risk_level": "MODERATE",
        "scan_results": {
            "dns": {
                "ipv4": ["1.2.3.4", "5.6.7.8"]
            }
        }
    }

    result = compare_scans(previous, current)

    print(result)  # Debugging line to print the result
    assert "dns" in result
    assert "5.6.7.8" in result["dns"]["ipv4"]["added"]


def test_ipv4_removed():

    previous = {
        "risk_score": 20,
        "risk_level": "MODERATE",
        "scan_results": {
            "dns": {
                "ipv4": ["1.2.3.4", "5.6.7.8"]
            }
        }
    }

    current = {
        "risk_score": 20,
        "risk_level": "MODERATE",
        "scan_results": {
            "dns": {
                "ipv4": ["1.2.3.4"]
            }
        }
    }

    result = compare_scans(previous, current)

    assert "dns" in result
    assert "5.6.7.8" in result["dns"]["ipv4"]["removed"]