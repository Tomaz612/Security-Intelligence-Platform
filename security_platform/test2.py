from threat_intelligence import check_virustotal_ip, check_abuseipdb


ip = "8.8.8.8"

print("\nVirusTotal:")
print(check_virustotal_ip(ip))

print("\nAbuseIPDB:")
print(check_abuseipdb(ip))