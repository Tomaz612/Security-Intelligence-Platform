from scanner import scan_target
from detection import run_detections
from risk import assess_risk
from database import get_previous_scan, save_scan
from comparison import compare_scans


def print_historical_analysis(comparison):
    print("\nHistorical Analysis:")
    print("-" * 20)

    if not comparison:
        print("No changes detected.")
        return

    # Risk changes
    if "risk" in comparison:
        risk = comparison["risk"]

        if "risk_score" in risk:
            previous = risk["risk_score"]["previous"]
            current = risk["risk_score"]["current"]

            print(f"Risk Score: {previous} -> {current}")

        if "risk_level" in risk:
            previous = risk["risk_level"]["previous"]
            current = risk["risk_level"]["current"]

            print(f"Risk Level: {previous} -> {current}")

    # Port changes
    if "ports" in comparison:
        ports = comparison["ports"]

        if ports["opened"]:
            print("\nPorts Opened:")

            for port in sorted(ports["opened"]):
                print(f"  [NEW] Port {port} is now open.")

        if ports["closed"]:
            print("\nPorts Closed:")

            for port in sorted(ports["closed"]):
                print(f"  [CLOSED] Port {port} is no longer open.")

    # DNS changes
    if "dns" in comparison:
        dns = comparison["dns"]

        if "ipv4" in dns:
            ipv4 = dns["ipv4"]

            if ipv4["added"]:
                print("\nIPv4 Addresses Added:")

                for address in sorted(ipv4["added"]):
                    print(f"  [ADDED] {address}")

            if ipv4["removed"]:
                print("\nIPv4 Addresses Removed:")

                for address in sorted(ipv4["removed"]):
                    print(f"  [REMOVED] {address}")

        if "ipv6" in dns:
            ipv6 = dns["ipv6"]

            if ipv6["added"]:
                print("\nIPv6 Addresses Added:")

                for address in sorted(ipv6["added"]):
                    print(f"  [ADDED] {address}")

            if ipv6["removed"]:
                print("\nIPv6 Addresses Removed:")

                for address in sorted(ipv6["removed"]):
                    print(f"  [REMOVED] {address}")

def main():
    target = input("Enter IP or domain: ")

    # Get previous scan
    previous_scan = get_previous_scan(target)

    # Perform current scan
    scan_results = scan_target(target)

    # Detection Engine
    findings = run_detections(scan_results)

    # Risk Assessment
    risk = assess_risk(findings)

    # Current scan object
    current_scan = {
        "target": target,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "scan_results": scan_results
    }

    # Historical comparison
    if previous_scan:
        comparison = compare_scans(previous_scan, current_scan)
        print_historical_analysis(comparison)

    else:
        print("\nHistorical Analysis:")
        print("-" * 20)
        print("No previous scan found.")

    # Save current scan
    save_scan(
        target,
        risk["score"],
        risk["level"],
        scan_results
    )

    # Results
    print("\nRisk Assessment:")
    print("-" * 20)
    print(f"Risk Score: {risk['score']}/100")
    print(f"Risk Level: {risk['level']}")

    print("\nSecurity Findings:")
    if findings:
        for finding in findings:
            print(f"\n[{finding['severity']}] {finding['title']}")
            print(f"  Rule: {finding['rule_id']}")
            print(f"  Description: {finding['description']}")
            print(f"  Evidence: {finding['evidence']}")
            print(f"  Protocol: {finding['protocol']}")
            print(f"  Recommendation: {finding['recommendation']}")
    else:
        print("  No security findings detected.")



if __name__ == "__main__":
    main()