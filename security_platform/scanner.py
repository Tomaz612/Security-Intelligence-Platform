import socket
import ipaddress
import dns.resolver
import urllib.request
import ssl
from detection import run_detections
from risk import assess_risk

ports = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    3389   # RDP
]

# Determine if the input is an IP address or a domain name
def distinction(name):
    try:
        ipaddress.ip_address(name)
        return "IP address"
    except ValueError:
        return "Domain name"

# Resolve the IP addresses for a given domain and address family (IPv4 or IPv6)
def resolve_addresses(domain, address_family):

    try:
        result = socket.getaddrinfo(domain, None, address_family)

        addresses = []

        for address in result:
            ip = address[4][0]

            if ip not in addresses:
                addresses.append(ip)

        return addresses

    except socket.gaierror:
        return []


# Resolve the nameservers for a given domain
def resolve_record(domain, record_type):
    try:
        result = dns.resolver.resolve(domain, record_type)

        records = []

        for record in result:
            if record_type == "MX":
                records.append((record.preference, str(record.exchange)))
            else:
                records.append(str(record))

        return records

    except dns.resolver.NXDOMAIN:
        return []

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.NoNameservers:
        return []


# Resolve the PTR records for a given IP address
def resolve_ptr(ip):
    try:
        reverse_name = dns.reversename.from_address(ip)
        result = dns.resolver.resolve(reverse_name, "PTR")

        hostnames = []

        for record in result:
            hostnames.append(str(record))

        return hostnames

    except dns.resolver.NXDOMAIN:
        return []

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.NoNameservers:
        return []



# HTTP/HTTPS analysis for a given domain

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

# Analyze HTTP and HTTPS responses for a given domain
def analyze_http(domain):
    results = {}

    opener = urllib.request.build_opener(NoRedirectHandler)

    for protocol in ["http", "https"]:
        url = f"{protocol}://{domain}"

        try:
            response = opener.open(url, timeout=5)

            results[protocol] = {
                "status_code": response.status,
                "url": response.url,
                "headers": dict(response.headers)
            }

        except urllib.error.HTTPError as e:
            results[protocol] = {
                "status_code": e.code,
                "url": e.url,
                "headers": dict(e.headers)
            }

        except Exception as e:
            results[protocol] = {
                "error": str(e)
            }
    return results


# Analyze security headers from the HTTP/HTTPS response headers
def analyze_security_headers(headers):
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    results = {}

    for header in security_headers:
        value = headers.get(header)

        results[header] = {
            "present": value is not None,
            "value": value
        }

    return results



# TLS Analysis

# Analyze TLS information for a given domain
def analyze_tls(domain):
    results = {}

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_socket:

                certificate = tls_socket.getpeercert()

                results = {
                    "tls_version": tls_socket.version(),
                    "cipher": tls_socket.cipher(),
                    "certificate": parse_certificate(certificate)
                }

    except Exception as e:
        results = {
            "error": str(e)
        }

    return results


# Parse the certificate information into a more readable format
def parse_certificate(certificate):
    subject = dict(x[0] for x in certificate.get("subject", ()))
    issuer = dict(x[0] for x in certificate.get("issuer", ()))

    san = [
        value
        for name, value in certificate.get("subjectAltName", ())
        if name == "DNS"
    ]

    return {
        "subject": subject.get("commonName"),
        "issuer": issuer.get("commonName"),
        "valid_from": certificate.get("notBefore"),
        "valid_until": certificate.get("notAfter"),
        "san": san
    }


# TCP Port Scanning

def scan_ports(domain, ports):
    results = {}

    for port in ports:
        try:
            with socket.create_connection((domain, port), timeout=1):
                results[port] = "open"

        except (socket.timeout, ConnectionRefusedError):
            results[port] = "closed"

        except OSError:
            results[port] = "filtered"

    return results



def print_results(title, results):
    print(f"\n{title}")
    if results:
        for result in results:
            print(f"  {result}")
    else:
        print("  No results found.")


def print_mx_records(results):
    print(f"\nMail servers (MX records):")

    if results:
        for priority, server in results:
            print(f"  {server} (priority: {priority})")
    else:
        print("  Not found")


def scan_target(name):
    target_type = distinction(name)

    if target_type == "Domain name":

        ipv4 = resolve_addresses(name, socket.AF_INET)
        ipv6 = resolve_addresses(name, socket.AF_INET6)
        ns = resolve_record(name, "NS")
        mx = resolve_record(name, "MX")
        txt = resolve_record(name, "TXT")
        cname = resolve_record(name, "CNAME")

        dns_results = {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "nameservers": ns,
            "mx": mx,
            "txt": txt,
            "cname": cname
        }

        http = analyze_http(name)
        tls = analyze_tls(name)
        port_results = scan_ports(name, ports)

        scan_results = {
            "target": name,
            "dns": dns_results,
            "http": http,
            "tls": tls,
            "ports": port_results
        }

    elif target_type == "IP address":

            dns_results = {
                "ipv4": [name],
                "ipv6": [],
                "nameservers": [],
                "mx": [],
                "txt": [],
                "cname": []
            }

            http = analyze_http(name)
            tls = analyze_tls(name)
            port_results = scan_ports(name, ports)

    else:
        return None

    scan_results = {
        "target": name,
        "dns": dns_results,
        "http": http,
        "tls": tls,
        "ports": port_results
    }

    return scan_results

def main():
    name = input("Enter IP or domain: ")

    scan_results = scan_target(name)

    print("\nScan results:")
    print(scan_results)

    findings = run_detections(scan_results)

    risk = assess_risk(findings)

    print("\nRisk Assessment:")
    print(f"Risk Score: {risk['score']}/100")
    print(f"Risk Level: {risk['level']}")
