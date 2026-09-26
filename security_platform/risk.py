

def calculate_risk_score(threat_intelligence):

    abuseipdb = threat_intelligence.get("abuseipdb", {})

    scores = []

    for ip, data in abuseipdb.items():

        if not data.get("available", True):
            continue

        score = data.get("abuse_confidence_score")

        if score is not None:
            scores.append({
                "ip": ip,
                "score": score
            })

    if not scores:
        return None, None

    highest = max(scores, key=lambda item: item["score"])

    return highest["score"], highest["ip"]


def calculate_risk_level(score):

    if score is None:
        return "UNKNOWN"

    if score >= 75:
        return "CRITICAL"

    elif score >= 50:
        return "HIGH"

    elif score >= 25:
        return "MODERATE"

    else:
        return "LOW"



def assess_risk(threat_intelligence):

    score, source_ip = calculate_risk_score(threat_intelligence)

    level = calculate_risk_level(score)

    return {
        "score": score,
        "level": level,
        "source": "AbuseIPDB" if score is not None else None,
        "source_ip": source_ip
    }