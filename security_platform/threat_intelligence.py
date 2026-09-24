import os
import requests
from dotenv import load_dotenv

load_dotenv()


def check_virustotal_ip(ip):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "available": False,
            "error": "VirusTotal API request failed."
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            return {
                "error": "IP not found in VirusTotal."
            }

        if response.status_code == 429:
            return {
                "available": False,
                "error": "Rate limit exceeded."
            }

        if not response.ok:
            return {
                "available": False,
                "error": f"API request failed with status code {response.status_code}."
            }

        response.raise_for_status()

        data = response.json()["data"]["attributes"]

        return {
            "reputation": data.get("reputation"),
            "malicious": data.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious": data.get("last_analysis_stats", {}).get("suspicious", 0),
            "harmless": data.get("last_analysis_stats", {}).get("harmless", 0),
            "undetected": data.get("last_analysis_stats", {}).get("undetected", 0)
        }

    except requests.RequestException as e:
        return {
            "error": str(e)
        }


def check_abuseipdb(ip):
    api_key = os.getenv("ABUSE_API_KEY")

    if not api_key:
        return {
            "available": False,
            "error": "API key not configured."
        }
    
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code == 429:
            return {
                "available": False,
                "error": "Rate limit exceeded."
            }

        if not response.ok:
            return {
                "available": False,
                "error": f"API request failed with status code {response.status_code}."
            }

        response.raise_for_status()

        data = response.json()["data"]

        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "last_reported_at": data.get("lastReportedAt")
        }

    except requests.RequestException as e:
        return {
            "error": str(e)
        }



def enrich_target(scan_results):
    threat_intelligence = {
        "virustotal": {},
        "abuseipdb": {}
    }

    ipv4_addresses = scan_results.get("dns", {}).get("ipv4", [])

    if not ipv4_addresses:
        return threat_intelligence

    for ip in ipv4_addresses:
        threat_intelligence["virustotal"][ip] = check_virustotal_ip(ip)
        threat_intelligence["abuseipdb"][ip] = check_abuseipdb(ip)

    return threat_intelligence