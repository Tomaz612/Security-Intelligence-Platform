async function runScan() {

    const target = document.getElementById("target").value.trim();

    if (!target) {
        alert("Please enter an IP address or domain.");
        return;
    }

    const results = document.getElementById("results");
    const loading = document.getElementById("loading");

    results.classList.add("hidden");
    loading.classList.remove("hidden");

    try {

        const response = await fetch(
            `/scan/${encodeURIComponent(target)}`
        );

        if (!response.ok) {
            throw new Error("Scan failed");
        }

        const data = await response.json();

        displayResults(data);

        results.classList.remove("hidden");

        } catch (error) {

            console.error("SCAN ERROR:", error);
            console.error("STACK:", error.stack);

            alert(
                `An error occurred while scanning the target.\n\n${error.message}`
            );
                
        } finally {

        loading.classList.add("hidden");
        }

function displayResults(data) {

    displayRisk(data.risk, data.findings);

    displayHistorical(data.historical_analysis);

    displayFindings(data.findings);

    displayNetwork(data.scan_results);

    displayDNS(data.scan_results.dns);

    displayTLS(data.scan_results.tls);

    displayThreatIntelligence(data.threat_intelligence);
}


function displayRisk(risk, findings) {

    const score = risk.score;
    const level = risk.level;

    const riskScoreElement = document.getElementById("risk-score");
    const riskLevelElement = document.getElementById("risk-level");

    const riskSourceElement = document.getElementById("risk-source");
    const riskSourceIpElement = document.getElementById("risk-source-ip");

    riskScoreElement.textContent =
        score !== null ? `${score} / 100` : "N/A";

    riskLevelElement.textContent = level;

    riskSourceElement.textContent =
    risk.source ? `Source: ${risk.source}` : "Source: Not available";

    riskSourceIpElement.textContent =
    risk.source_ip ? `Based on: ${risk.source_ip}` : "";

    // Apply risk level styling
    const riskClass = `risk-${level.toLowerCase()}`;

    riskScoreElement.className = `risk-score ${riskClass}`;
    riskLevelElement.className = `risk-label ${riskClass}`;

    // Update risk bar
    const riskBar = document.getElementById("risk-bar-fill");

    if (riskBar) {
        riskBar.style.width = `${score}%`;
        riskBar.className = `risk-bar-fill ${riskClass}`;
    }

    // Count findings by severity
    const severityCounts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
    };

    findings.forEach(finding => {

        const severity = finding.severity?.toUpperCase();

        if (severityCounts.hasOwnProperty(severity)) {
            severityCounts[severity]++;
        }

    });

    // Update counters
    document.getElementById("critical-count").textContent =
        severityCounts.CRITICAL;

    document.getElementById("high-count").textContent =
        severityCounts.HIGH;

    document.getElementById("medium-count").textContent =
        severityCounts.MEDIUM;

    document.getElementById("low-count").textContent =
        severityCounts.LOW;
}

function displayFindings(findings) {

    const container = document.getElementById("findings");

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="no-findings">
                No security findings detected.
            </div>
        `;
        return;
    }

    container.innerHTML = findings.map(finding => `
        <div class="finding">

            <div class="finding-header">

                <div class="finding-title">
                    <span class="finding-severity ${finding.severity.toLowerCase()}">
                        ${finding.severity}
                    </span>

                    <h3>${finding.title}</h3>
                </div>

                <div class="finding-meta">
                    ${finding.rule_id}
                    ${finding.protocol ? `• ${finding.protocol}` : ""}
                </div>

            </div>

            <p class="finding-description">
                ${finding.description}
            </p>

            <div class="finding-section">
                <span class="finding-label">Evidence</span>
                <p>${finding.evidence}</p>
            </div>

            <div class="finding-section">
                <span class="finding-label">Recommendation</span>
                <p>${finding.recommendation}</p>
            </div>

        </div>
    `).join("");
}


function displayNetwork(scanResults) {

    const container = document.getElementById("network");
    const ports = scanResults.ports;

    if (!ports || Object.keys(ports).length === 0) {
        container.innerHTML = `
            <div class="no-network">
                No port scan results available.
            </div>
        `;
        return;
    }

    const openPorts = Object.values(ports)
        .filter(status => status === "open")
        .length;

    const closedPorts = Object.values(ports)
        .filter(status => status === "closed")
        .length;

    let html = `
        <div class="network-summary">

            <div class="network-summary-item">
                <span class="network-summary-count open">
                    ${openPorts}
                </span>
                <span class="network-summary-label">
                    Open
                </span>
            </div>

            <div class="network-summary-item">
                <span class="network-summary-count closed">
                    ${closedPorts}
                </span>
                <span class="network-summary-label">
                    Closed
                </span>
            </div>

        </div>

        <table class="port-table">
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Status</th>
                </tr>
            </thead>

            <tbody>
    `;

    for (const [port, status] of Object.entries(ports)) {

        const service = getServiceName(port);

        const statusClass = status === "open"
            ? "status-open"
            : "status-closed";

        html += `
            <tr>
                <td>${port}</td>
                <td>${service}</td>
                <td>
                    <span class="${statusClass}">
                        ${status.toUpperCase()}
                    </span>
                </td>
            </tr>
        `;
    }

    html += `
            </tbody>
        </table>
    `;

    container.innerHTML = html;
}

function getServiceName(port) {

    const services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP"
    };

    return services[port] || "Unknown";
}



function displayDNS(dns) {

    const container = document.getElementById("dns");

    if (!dns) {
        container.innerHTML = "<p>No DNS information available.</p>";
        return;
    }

    let html = "";

    html += createDNSSection(
        "IPv4 Addresses",
        dns.ipv4
    );

    html += createDNSSection(
        "IPv6 Addresses",
        dns.ipv6
    );

    html += createDNSSection(
        "Nameservers",
        dns.nameservers
    );

    html += createDNSSection(
        "MX Records",
        dns.mx
    );

    html += createDNSSection(
        "TXT Records",
        dns.txt
    );

    html += createDNSSection(
        "CNAME Records",
        dns.cname
    );

    container.innerHTML = html;
}

function createDNSSection(title, values) {

    if (!values || values.length === 0) {
        return `
            <div class="dns-section">
                <h3>${title}</h3>
                <p class="dns-empty">No records found.</p>
            </div>
        `;
    }

    return `
        <div class="dns-section">
            <h3>${title}</h3>

            <ul>
                ${values.map(value => `
                    <li>${value}</li>
                `).join("")}
            </ul>
        </div>
    `;
}



function displayTLS(tls) {

    const container = document.getElementById("tls");

    if (!tls || tls.error) {
        container.innerHTML = "<p>TLS information not available.</p>";
        return;
    }

    const cipher = tls.cipher
        ? tls.cipher[0]
        : "Unknown";

    const certificate = tls.certificate;

    let html = `
        <div class="tls-overview">

            <div class="tls-item">
                <span class="tls-label">TLS Version</span>
                <strong>${tls.tls_version || "Unknown"}</strong>
            </div>

            <div class="tls-item">
                <span class="tls-label">Cipher</span>
                <strong>${cipher}</strong>
            </div>

        </div>
    `;

    if (certificate) {

        html += `
            <div class="certificate">

                <h3>Certificate</h3>

                <div class="certificate-grid">

                    <div>
                        <span class="tls-label">Subject</span>
                        <p>${certificate.subject || "Unknown"}</p>
                    </div>

                    <div>
                        <span class="tls-label">Issuer</span>
                        <p>${certificate.issuer || "Unknown"}</p>
                    </div>

                    <div>
                        <span class="tls-label">Valid From</span>
                        <p>${certificate.valid_from || "Unknown"}</p>
                    </div>

                    <div>
                        <span class="tls-label">Valid Until</span>
                        <p>${certificate.valid_until || "Unknown"}</p>
                    </div>

                </div>

                <div class="certificate-san">

                    <span class="tls-label">
                        Subject Alternative Names
                    </span>

                    <ul>
                        ${
                            certificate.san && certificate.san.length
                            ? certificate.san.map(name => `<li>${name}</li>`).join("")
                            : "<li>No SAN entries found.</li>"
                        }
                    </ul>

                </div>

            </div>
        `;
    }

    container.innerHTML = html;
}


function displayThreatIntelligence(threatIntelligence) {

    const container = document.getElementById("threat-intelligence");

    if (!threatIntelligence) {
        container.innerHTML = "<p>No threat intelligence available.</p>";
        return;
    }

    let html = "";

    const virustotal = threatIntelligence.virustotal || {};
    const abuseipdb = threatIntelligence.abuseipdb || {};

    const ips = new Set([
        ...Object.keys(virustotal),
        ...Object.keys(abuseipdb)
    ]);

    if (ips.size === 0) {
        container.innerHTML = "<p>No threat intelligence data available.</p>";
        return;
    }

    for (const ip of ips) {

        const vt = virustotal[ip];
        const abuse = abuseipdb[ip];

        html += `
            <div class="ti-ip-card">

                <h3>${ip}</h3>

                <div class="ti-grid">

                    <div class="ti-provider">
                        <h4>VirusTotal</h4>

                        ${
                            vt
                                ? displayVirusTotal(vt)
                                : "<p>No data available.</p>"
                        }
                    </div>

                    <div class="ti-provider">
                        <h4>AbuseIPDB</h4>

                        ${
                            abuse
                                ? displayAbuseIPDB(abuse)
                                : "<p>No data available.</p>"
                        }
                    </div>

                </div>

            </div>
        `;
    }

    container.innerHTML = html;
}

function displayVirusTotal(data) {

    if (data.error) {
        return `
            <p class="ti-error">
                ${data.error}
            </p>
        `;
    }

    if (data.available === false) {
        return `
            <p class="ti-muted">
                Data not available.
            </p>
        `;
    }

    return `
        <div class="ti-stat">
            <span>Reputation</span>
            <strong>${data.reputation ?? "N/A"}</strong>
        </div>

        <div class="ti-stat">
            <span>Malicious</span>
            <strong>${data.malicious ?? 0}</strong>
        </div>

        <div class="ti-stat">
            <span>Suspicious</span>
            <strong>${data.suspicious ?? 0}</strong>
        </div>

        <div class="ti-stat">
            <span>Harmless</span>
            <strong>${data.harmless ?? 0}</strong>
        </div>

        <div class="ti-stat">
            <span>Undetected</span>
            <strong>${data.undetected ?? 0}</strong>
        </div>
    `;
}


function displayAbuseIPDB(data) {

    if (data.error) {
        return `
            <p class="ti-error">
                ${data.error}
            </p>
        `;
    }

    if (data.available === false) {
        return `
            <p class="ti-muted">
                Data not available.
            </p>
        `;
    }

    return `
        <div class="ti-stat">
            <span>Abuse Confidence Score</span>
            <strong>${data.abuse_confidence_score ?? "N/A"}</strong>
        </div>

        <div class="ti-stat">
            <span>Total Reports</span>
            <strong>${data.total_reports ?? 0}</strong>
        </div>

        <div class="ti-stat">
            <span>Country</span>
            <strong>${data.country_code || "N/A"}</strong>
        </div>

        <div class="ti-stat">
            <span>ISP</span>
            <strong>${data.isp || "N/A"}</strong>
        </div>

        <div class="ti-stat">
            <span>Domain</span>
            <strong>${data.domain || "N/A"}</strong>
        </div>

        <div class="ti-stat">
            <span>Last Reported</span>
            <strong>${data.last_reported_at || "N/A"}</strong>
        </div>
    `;
}


function displayHistorical(historical) {

    const container = document.getElementById("historical-analysis");

    // First scan
    if (!historical) {
        container.innerHTML = `
            <p class="history-empty">
                No previous scan available for this target.
            </p>
        `;
        return;
    }

    // Previous scan exists, but nothing changed
    if (Object.keys(historical).length === 0) {
        container.innerHTML = `
            <div class="history-no-changes">
                <strong>No changes detected</strong>
                <p>
                    The current scan is consistent with the previous scan.
                </p>
            </div>
        `;
        return;
    }

    let html = "";

    if (historical.risk) {

        html += `
            <div class="history-section">
                <h3>Risk Assessment</h3>

                <div class="history-grid">

                    <div class="history-item">
                        <span>Previous Score</span>
                        <strong>${historical.risk.previous_score}</strong>
                    </div>

                    <div class="history-item">
                        <span>Current Score</span>
                        <strong>${historical.risk.current_score}</strong>
                    </div>

                    <div class="history-item">
                        <span>Change</span>
                        <strong>
                            ${formatChange(historical.risk.change)}
                        </strong>
                    </div>

                </div>
            </div>
        `;
    }

    if (historical.ports) {

        html += `
            <div class="history-section">
                <h3>Port Changes</h3>

                ${displayPortChanges(historical.ports)}
            </div>
        `;
    }

    if (historical.dns) {

        html += `
            <div class="history-section">
                <h3>DNS Changes</h3>

                ${displayDNSChanges(historical.dns)}
            </div>
        `;
    }

    container.innerHTML = html;
}



function displayPortChanges(ports) {

    let html = "";

    const opened = ports.opened || [];
    const closed = ports.closed || [];

    if (opened.length > 0) {

        html += `
            <div class="change-group">
                <h4>Newly Opened</h4>

                <ul>
                    ${opened.map(port => `
                        <li class="change-open">
                            Port ${port} is now open
                        </li>
                    `).join("")}
                </ul>
            </div>
        `;
    }

    if (closed.length > 0) {

        html += `
            <div class="change-group">
                <h4>Newly Closed</h4>

                <ul>
                    ${closed.map(port => `
                        <li class="change-closed">
                            Port ${port} is now closed
                        </li>
                    `).join("")}
                </ul>
            </div>
        `;
    }

    if (!html) {
        html = "<p>No port changes detected.</p>";
    }

    return html;
}


function displayDNSChanges(dns) {

    let html = "";

    const addedIPv4 = dns.added_ipv4 || [];
    const removedIPv4 = dns.removed_ipv4 || [];

    const addedIPv6 = dns.added_ipv6 || [];
    const removedIPv6 = dns.removed_ipv6 || [];

    if (addedIPv4.length > 0) {

        html += `
            <div class="change-group">
                <h4>IPv4 Added</h4>

                <ul>
                    ${addedIPv4.map(ip => `
                        <li class="change-added">
                            ${ip}
                        </li>
                    `).join("")}
                </ul>
            </div>
        `;
    }

    if (removedIPv4.length > 0) {

        html += `
            <div class="change-group">
                <h4>IPv4 Removed</h4>

                <ul>
                    ${removedIPv4.map(ip => `
                        <li class="change-removed">
                            ${ip}
                        </li>
                    `).join("")}
                </ul>
            </div>
        `;
    }

    if (addedIPv6.length > 0) {

        html += `
            <div class="change-group">
                <h4>IPv6 Added</h4>

                <ul>
                    ${addedIPv6.map(ip => `
                        <li class="change-added">
                            ${ip}
                        </li>
                    `).join("")}
                </ul>
            </div>
        `;
    }

    if (removedIPv6.length > 0) {

        html += `
            <div class="change-group">
                <h4>IPv6 Removed</h4>

                <ul>
                    ${removedIPv6.map(ip => `
                        <li class="change-removed">
                            ${ip}
                        </li>
                    `).join("")}
                </ul>
            </div>
        `;
    }

    if (!html) {
        html = "<p>No DNS changes detected.</p>";
    }

    return html;
}


function formatChange(change) {

    if (change > 0) {
        return `+${change}`;
    }

    return change;
}

}


document.addEventListener("click", function (event) {

    const tab = event.target.closest(".tab");

    if (!tab) {
        return;
    }

    const target = tab.dataset.tab;

    document.querySelectorAll(".tab").forEach(t => {
        t.classList.remove("active");
    });

    document.querySelectorAll(".tab-content").forEach(content => {
        content.classList.remove("active");
    });

    tab.classList.add("active");

    const selectedContent = document.getElementById(`tab-${target}`);

    if (selectedContent) {
        selectedContent.classList.add("active");
    }

});