import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security_platform.risk import (
    calculate_risk_score,
    calculate_risk_level,
    assess_risk
)

def test_abuseipdb_score_zero():
    threat_intelligence = {
        "abuseipdb": {
            "8.8.8.8": {
                "abuse_confidence_score": 0
            }
        }
    }

    score, source_ip = calculate_risk_score(threat_intelligence)

    assert score == 0
    assert source_ip == "8.8.8.8"


def test_abuseipdb_score_25():
    assert calculate_risk_level(25) == "MODERATE"


def test_abuseipdb_score_50():
    assert calculate_risk_level(50) == "HIGH"


def test_abuseipdb_score_75():
    assert calculate_risk_level(75) == "CRITICAL"


def test_abuseipdb_score_below_25():
    assert calculate_risk_level(24) == "LOW"


def test_abuseipdb_score_below_50():
    assert calculate_risk_level(49) == "MODERATE"


def test_abuseipdb_score_below_75():
    assert calculate_risk_level(74) == "HIGH"


def test_no_abuseipdb_data():
    threat_intelligence = {
        "abuseipdb": {}
    }

    score, source_ip = calculate_risk_score(threat_intelligence)

    assert score is None
    assert source_ip is None


def test_multiple_ips_uses_highest_score():
    threat_intelligence = {
        "abuseipdb": {
            "1.1.1.1": {
                "abuse_confidence_score": 10
            },
            "2.2.2.2": {
                "abuse_confidence_score": 80
            },
            "3.3.3.3": {
                "abuse_confidence_score": 40
            }
        }
    }

    score, source_ip = calculate_risk_score(threat_intelligence)

    assert score == 80
    assert source_ip == "2.2.2.2"


def test_assess_risk():
    threat_intelligence = {
        "abuseipdb": {
            "1.2.3.4": {
                "abuse_confidence_score": 60
            }
        }
    }

    result = assess_risk(threat_intelligence)

    assert result["score"] == 60
    assert result["level"] == "HIGH"
    assert result["source"] == "AbuseIPDB"
    assert result["source_ip"] == "1.2.3.4"