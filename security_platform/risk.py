SEVERITY_POINTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 2,
    "INFO": 0
}



def calculate_risk_score(findings):

    low = 0
    medium = 0
    high = 0
    critical = 0

    score = 0

    for finding in findings:

        severity = finding.get("severity", "INFO")

        if severity == "LOW":
            low += 2
        elif severity == "MEDIUM":
            medium += 15
        elif severity == "HIGH":
            high += 25
        elif severity == "CRITICAL":
            critical += 40

        score += SEVERITY_POINTS.get(severity, 0)

    return min(score, 100), (low, medium, high, critical)


def calculate_risk_level(score):

    if score >= 70:
        return "CRITICAL"

    elif score >= 40:
        return "HIGH"

    elif score >= 20:
        return "MODERATE"

    else:
        return "LOW"

    

def assess_risk(findings):

    score, breakdown = calculate_risk_score(findings)
    level = calculate_risk_level(score)


    return {
        "score": score,
        "level": level,
        "breakdown": {
            "low": breakdown[0],
            "medium": breakdown[1],
            "high": breakdown[2],
            "critical": breakdown[3]
        }
    }
