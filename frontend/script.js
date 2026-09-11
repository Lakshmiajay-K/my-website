const emailFile = document.getElementById("emailFile");
const fileName = document.getElementById("fileName");
const analyzeButton = document.getElementById("analyzeButton");
const statusBox = document.getElementById("status");
const results = document.getElementById("results");


// =====================================================
// File Selection
// =====================================================

emailFile.addEventListener("change", function () {

    if (emailFile.files.length > 0) {

        fileName.textContent =
            emailFile.files[0].name;

        statusBox.textContent =
            "Email file selected.";

    } else {

        fileName.textContent =
            "Click to select an email file";

        statusBox.textContent = "";
    }
});


// =====================================================
// Analyze Email
// =====================================================

async function analyzeEmail() {

    if (emailFile.files.length === 0) {

        statusBox.textContent =
            "Please select an .eml file first.";

        return;
    }

    const file = emailFile.files[0];

    if (!file.name.toLowerCase().endsWith(".eml")) {

        statusBox.textContent =
            "Only .eml files are supported.";

        return;
    }

    const formData = new FormData();

    formData.append(
        "file",
        file
    );

    analyzeButton.disabled = true;

    analyzeButton.textContent =
        "Analyzing...";

    statusBox.textContent =
        "Analyzing email. Please wait...";

    try {

        const response = await fetch(
            "http://127.0.0.1:8000/analyze-email",
            {
                method: "POST",
                body: formData
            }
        );

        if (!response.ok) {

            throw new Error(
                "Server returned an error."
            );
        }

        const data =
            await response.json();

        displayResults(data);

        statusBox.textContent =
            "Analysis completed successfully.";

    } catch (error) {

        console.error(
            "FRONTEND ERROR:",
            error
        );

        statusBox.textContent =
            "Cannot connect to the email analysis server.";

    } finally {

        analyzeButton.disabled = false;

        analyzeButton.textContent =
            "Analyze Email";
    }
}


// =====================================================
// Main Results
// =====================================================

function displayResults(data) {

    const email =
        data.email || {};

    const analysis =
        data.threat_analysis || {};

    results.style.display =
        "block";
        
     displayThreatSummary(
        analysis,
        email
    );
    const auth =
        analysis.authentication_analysis || {};

    const attachment =
        analysis.attachment_analysis || [];

    const correlation =
        analysis.correlation_analysis || {};

    const evidence = [];

    if (
        auth.spf?.status === "FAIL" ||
        auth.dkim?.status === "FAIL" ||
        auth.dmarc?.status === "FAIL"
    ) {
        evidence.push("🔐 Authentication Failure");
    }

    if (
        email.from &&
        email.reply_to &&
        JSON.stringify(email.from) !==
        JSON.stringify(email.reply_to)
    ) {
        evidence.push("📨 Header Mismatch");
    }

    if (
        attachment.some(
            item => item.score >= 50
        )
    ) {
        evidence.push("📎 Malicious Attachment");
    }

    if (
        analysis.content_analysis?.score >= 10
    ) {
        evidence.push("🧠 Phishing Language");
    }

    if (
        correlation.score > 0
    ) {
        evidence.push("🔗 Correlated Evidence");
    }


    // -------------------------------------------------
    // Threat Score
    // -------------------------------------------------

    const score =
        Number(
            analysis.threat_score || 0
        );

    let scoreClass = "safe";

    if (score >= 60) {

        scoreClass = "malicious";

    } else if (score >= 30) {

        scoreClass = "suspicious";
    }


    const scoreElement =
        document.getElementById(
            "threatScore"
        );

    if (scoreElement) {

        scoreElement.textContent =
            score;

        scoreElement.className =
            "threat-score " + scoreClass;
    }


    const scoreFill =
        document.getElementById(
            "scoreFill"
        );

    if (scoreFill) {

        scoreFill.style.width =
            score + "%";

        scoreFill.className =
            "score-fill " + scoreClass;
    }


    // -------------------------------------------------
    // Classification
    // -------------------------------------------------

    const classificationElement =
        document.getElementById(
            "classification"
        );

    if (classificationElement) {

        classificationElement.textContent =
            analysis.classification || "UNKNOWN";

        classificationElement.className =
            "classification " +
            (
                analysis.classification ||
                "unknown"
            ).toLowerCase();
    }


    // -------------------------------------------------
    // Basic Email Information
    // -------------------------------------------------

    setText(
        "sender",
        analysis.sender_analysis?.sender || "--"
    );

    setText(
        "subject",
        email.subject || "--"
    );

    setText(
        "senderDomain",
        analysis.sender_analysis?.domain || "--"
    );

    setText(
        "urlCount",
        (analysis.url_analysis || []).length
    );


    // -------------------------------------------------
    // Existing Sections
    // -------------------------------------------------

    displayIndicators(
        analysis.indicators || []
    );

    displayAuthentication(
        email.authentication_results
    );

    displaySenderVerification(
        email.from,
        email.reply_to
    );

    displayUrlAnalysis(
        analysis.url_analysis || []
    );

    displayDomainAnalysis(
        analysis.domain_analysis || []
    );

    displayIPAnalysis(
        analysis.ip_analysis
    );

    displayAttachmentAnalysis(
        analysis.attachment_analysis || []
    );

    displayGeoAnalysis(
        data.geo_analysis
    );

    displayRiskBreakdown(
        analysis.risk_breakdown || {}
    );

    displayTimeline(
        analysis.forensic_timeline || []
    );


    // -------------------------------------------------
    // New SIH Intelligence Sections
    // -------------------------------------------------

    displayConfidence(
        analysis.confidence
    );

    displayImpersonation(
        analysis.impersonation_analysis || []
    );

    displayContentIntelligence(
        analysis.content_analysis
    );

    displayCorrelation(
        analysis.correlation_analysis
    );

    displayForensicSummary(
        data.forensic_report
    );


    // -------------------------------------------------
    // Report Export
    // -------------------------------------------------

    setupReportExport(
        data.forensic_report || data
    );


    // -------------------------------------------------
    // Scroll
    // -------------------------------------------------

    results.scrollIntoView({
        behavior: "smooth"
    });
}


// =====================================================
// Helper
// =====================================================

function setText(id, value) {

    const element =
        document.getElementById(id);

    if (element) {

        element.textContent =
            value;
    }
}


// =====================================================
// Threat Indicators
// =====================================================

function displayIndicators(indicators) {

    const container =
        document.getElementById(
            "indicators"
        );

    if (!container) return;

    container.innerHTML = "";

    if (!indicators.length) {

        container.innerHTML =
            "<li>No threat indicators detected.</li>";

        return;
    }

    indicators.forEach(
        function (indicator) {

            const item =
                document.createElement("li");

            item.textContent =
                indicator;

            container.appendChild(item);
        }
    );
}


// =====================================================
// Authentication
// =====================================================

function displayAuthentication(auth) {

    const container =
        document.getElementById(
            "authenticationAnalysis"
        );

    if (!container) return;

    container.innerHTML = "";

    if (!auth) {

        container.textContent =
            "No authentication results available.";

        return;
    }

    const methods = [
        "spf",
        "dkim",
        "dmarc"
    ];

    methods.forEach(
        function (method) {

            const match =
                String(auth)
                    .toLowerCase()
                    .match(
                        new RegExp(
                            method + "=([a-z]+)"
                        )
                    );

            const result =
                match
                    ? match[1].toUpperCase()
                    : "UNKNOWN";

            const box =
                document.createElement("div");

            box.className =
                "analysis-item";

            box.innerHTML = `
                <strong>${method.toUpperCase()}</strong>
                Result: ${escapeHtml(result)}
            `;

            container.appendChild(box);
        }
    );
}


// =====================================================
// Sender Verification
// =====================================================

function displaySenderVerification(
    from,
    replyTo
) {

    const container =
        document.getElementById(
            "senderVerification"
        );

    if (!container) return;

    container.innerHTML = "";

    const sender =
        from && from.length
            ? from[0][1]
            : "Unknown";

    const reply =
        replyTo && replyTo.length
            ? replyTo[0][1]
            : "Not specified";

    const senderDomain =
        sender.includes("@")
            ? sender.split("@").pop()
            : "Unknown";

    const replyDomain =
        reply.includes("@")
            ? reply.split("@").pop()
            : "Unknown";

    const matches =
        sender.toLowerCase() ===
        reply.toLowerCase();

    const box =
        document.createElement("div");

    box.className =
        "analysis-item";

    box.innerHTML = `
        <strong>From Address</strong>
        ${escapeHtml(sender)}

        <br><br>

        <strong>Reply-To Address</strong>
        ${escapeHtml(reply)}

        <br><br>

        <strong>Sender Domain</strong>
        ${escapeHtml(senderDomain)}

        <br><br>

        <strong>Reply-To Domain</strong>
        ${escapeHtml(replyDomain)}

        <br><br>

        <strong>Verification</strong>
        ${
            matches
                ? "✓ Addresses match"
                : "⚠ From and Reply-To addresses do not match"
        }
    `;

    container.appendChild(box);
}


// =====================================================
// URL Intelligence
// =====================================================

function displayUrlAnalysis(urls) {

    const container =
        document.getElementById(
            "urlAnalysis"
        );

    if (!container) return;

    container.innerHTML = "";

    if (!urls.length) {

        container.textContent =
            "No URLs detected.";

        return;
    }

    urls.forEach(
        function (item) {

            const box =
                document.createElement("div");

            box.className =
                "analysis-item";

            box.innerHTML = `
                <strong>
                    ${escapeHtml(item.url)}
                </strong>

                <br>

                Domain:
                ${escapeHtml(item.domain || "--")}

                <br>

                Score:
                ${item.score}

                <br>

                Classification:
                ${escapeHtml(item.classification)}

                <br><br>

                Indicators:
                ${
                    item.indicators?.length
                        ? item.indicators
                            .map(
                                x =>
                                    `<br>• ${escapeHtml(x)}`
                            )
                            .join("")
                        : "<br>None"
                }
            `;

            container.appendChild(box);
        }
    );
}


// =====================================================
// Domain Intelligence
// =====================================================

function displayDomainAnalysis(domains) {

    const container =
        document.getElementById(
            "domainAnalysis"
        );

    if (!container) return;

    container.innerHTML = "";

    if (!domains.length) {

        container.textContent =
            "No domain intelligence available.";

        return;
    }

    domains.forEach(
        function (item) {

            const box =
                document.createElement("div");

            box.className =
                "analysis-item";

            box.innerHTML = `
                <strong>
                    ${escapeHtml(item.domain)}
                </strong>

                <br>

                Status:
                ${escapeHtml(item.status)}

                <br>

                DNS Score:
                ${item.score}

                <br>

                Classification:
                ${escapeHtml(item.classification)}

                <br><br>

                A Records:
                ${
                    item.a_records?.length
                        ? escapeHtml(
                            item.a_records.join(", ")
                        )
                        : "--"
                }

                <br>

                MX Records:
                ${
                    item.mx_records?.length
                        ? escapeHtml(
                            item.mx_records.join(", ")
                        )
                        : "--"
                }
            `;

            container.appendChild(box);
        }
    );
}


// =====================================================
// IP Intelligence
// =====================================================

function displayIPAnalysis(ipAnalysis) {

    const container =
        document.getElementById(
            "ipAnalysis"
        );

    if (!container) return;

    container.innerHTML = "";

    if (!ipAnalysis || !ipAnalysis.ip) {

        container.textContent =
            "No IP intelligence available.";

        return;
    }

    const box =
        document.createElement("div");

    box.className =
        "analysis-item";

    const indicators =
        ipAnalysis.indicators || [];

    box.innerHTML = `
        <strong>Sender IP</strong>
        ${escapeHtml(ipAnalysis.ip)}

        <br><br>

        <strong>Risk Score</strong>
        ${ipAnalysis.score}

        <br><br>

        <strong>Classification</strong>
        ${escapeHtml(ipAnalysis.classification)}

        <br><br>

        <strong>Indicators</strong>
        ${
            indicators.length
                ? indicators
                    .map(
                        x =>
                            `<br>• ${escapeHtml(x)}`
                    )
                    .join("")
                : "<br>None"
        }
    `;

    container.appendChild(box);
}


// =====================================================
// Attachment Intelligence
// =====================================================

function displayAttachmentAnalysis(
    attachments
) {

    const container =
        document.getElementById(
            "attachmentAnalysis"
        );

    if (!container) return;

    container.innerHTML = "";

    if (!attachments.length) {

        container.textContent =
            "No attachments detected.";

        return;
    }

    attachments.forEach(
        function (item) {

            const box =
                document.createElement("div");

            box.className =
                "analysis-item";

            box.innerHTML = `
                <strong>
                    ${escapeHtml(item.filename)}
                </strong>

                <br>

                Type:
                ${escapeHtml(item.content_type)}

                <br>

                Extension:
                ${escapeHtml(item.extension)}

                <br>

                Risk Score:
                ${item.score}

                <br>

                Classification:
                ${escapeHtml(item.classification)}

                <br><br>

                Indicators:
                ${
                    item.indicators?.length
                        ? item.indicators
                            .map(
                                x =>
                                    `<br>• ${escapeHtml(x)}`
                            )
                            .join("")
                        : "<br>None"
                }
            `;

            container.appendChild(box);
        }
    );
}


// =====================================================
// GeoLocation
// =====================================================

function displayGeoAnalysis(geo) {

    const container =
        document.getElementById(
            "geoAnalysis"
        );

    if (!container) return;

    if (!geo || !geo.ip) {

        container.innerHTML =
            '<div class="geo-empty">No geolocation data available.</div>';

        return;
    }

    if (
        geo.status === "PRIVATE IP"
        || geo.status === "NO IP"
    ) {

        container.innerHTML = `
            <div class="geo-card private">

                <div class="geo-status">
                    ${escapeHtml(geo.status)}
                </div>

                <strong>IP:</strong>
                ${escapeHtml(geo.ip)}

                <br><br>

                ${
                    geo.indicators?.length
                        ? geo.indicators
                            .map(
                                x =>
                                    `• ${escapeHtml(x)}`
                            )
                            .join("<br>")
                        : "No additional information."
                }

            </div>
        `;

        return;
    }

    container.innerHTML = `
        <div class="geo-grid">

            ${geoItem("IP Address", geo.ip)}
            ${geoItem("Status", geo.status)}
            ${geoItem("Country", geo.country)}
            ${geoItem("Region", geo.region)}
            ${geoItem("City", geo.city)}
            ${geoItem("ISP", geo.isp)}
            ${geoItem("Organization", geo.organization)}
            ${geoItem("Timezone", geo.timezone)}
            ${geoItem("Latitude", geo.latitude)}
            ${geoItem("Longitude", geo.longitude)}

        </div>
    `;
}


function geoItem(label, value) {

    return `
        <div class="geo-item">

            <span>
                ${escapeHtml(label)}
            </span>

            <strong>
                ${escapeHtml(value ?? "--")}
            </strong>

        </div>
    `;
}


// =====================================================
// Risk Breakdown
// =====================================================

function displayRiskBreakdown(breakdown) {

    const container =
        document.getElementById("riskBreakdown");

    if (!container) return;

    container.innerHTML = `
        <div class="risk-note">
            Component scores show the strength of evidence from
            each intelligence layer. They are not portions of the
            final threat score and therefore do not need to total 100.
        </div>
    `;

    Object.entries(breakdown).forEach(
        function ([name, value]) {

            const score = Math.min(
                Number(value) || 0,
                100
            );

            const row =
                document.createElement("div");

            row.className = "risk-row";

            row.innerHTML = `
                <div class="risk-label">
                    <span>${escapeHtml(name)}</span>
                    <strong>${score}</strong>
                </div>

                <div class="risk-bar">
                    <div
                        class="risk-bar-fill"
                        style="width:${score}%"
                    ></div>
                </div>
            `;

            container.appendChild(row);
        }
    );
}


// =====================================================
// Forensic Timeline
// =====================================================

function displayTimeline(timeline) {

    const container =
        document.getElementById("timeline");

    if (!container) return;

    container.innerHTML = "";

    if (!timeline.length) {

        container.innerHTML =
            '<div class="empty-intelligence">No forensic events available.</div>';

        return;
    }

    timeline.forEach(
        function (item, index) {

            const box =
                document.createElement("div");

            box.className =
                "forensic-event";

            const hasTime =
                item.timestamp &&
                item.timestamp !==
                "Timestamp unavailable";

            let evidence =
                item.evidence;

            if (
                typeof evidence === "object"
            ) {

                evidence =
                    JSON.stringify(
                        evidence,
                        null,
                        2
                    );
            }

            box.innerHTML = `

                <div class="forensic-marker">
                    ${index + 1}
                </div>

                <div class="forensic-content">

                    <div class="forensic-title">
                        ${escapeHtml(
                            item.event ||
                            "Forensic Event"
                        )}
                    </div>

                    <div class="forensic-time ${
                        hasTime
                            ? "has-time"
                            : "no-time"
                    }">

                        ${
                            hasTime
                                ? "🕒 " +
                                  escapeHtml(
                                      item.timestamp
                                  )
                                : "Analysis event — exact timestamp unavailable"
                        }

                    </div>

                    ${
                        evidence
                            ? `
                                <pre class="forensic-evidence">${escapeHtml(
                                    String(evidence)
                                )}</pre>
                              `
                            : ""
                    }

                </div>
            `;

            container.appendChild(box);
        }
    );
}

// =====================================================
// STEP 38 — Confidence
// =====================================================

function displayConfidence(
    confidence
) {

    if (!confidence) return;

    const section =
        createDynamicSection(
            "confidenceSection",
            "🔎 Evidence Confidence"
        );

    section.innerHTML += `
        <div class="intelligence-grid">

            ${infoCard(
                "Confidence Score",
                confidence.confidence_score + "%"
            )}

            ${infoCard(
                "Confidence Level",
                confidence.confidence_level
            )}

            ${infoCard(
                "Evidence Count",
                confidence.evidence_count
            )}

            ${infoCard(
                "Strong Evidence",
                confidence.strong_evidence_count
            )}

        </div>

        <div class="explanation-box">
            ${escapeHtml(
                confidence.explanation || ""
            )}
        </div>
    `;
}


// =====================================================
// STEP 36 — Impersonation
// =====================================================

function displayImpersonation(
    impersonation
) {

    const section =
        createDynamicSection(
            "impersonationSection",
            "🎭 Impersonation Intelligence"
        );

    if (!impersonation.length) {

        section.innerHTML +=
            '<div class="empty-intelligence">No impersonation evidence detected.</div>';

        return;
    }

    impersonation.forEach(
        function (item) {

            section.innerHTML += `
                <div class="intelligence-card">

                    <div class="card-title">
                        ${escapeHtml(
                            item.domain || "--"
                        )}
                    </div>

                    ${infoLine(
                        "Matched Brand",
                        item.matched_brand || "None"
                    )}

                    ${infoLine(
                        "Risk Score",
                        item.score
                    )}

                    ${infoLine(
                        "Classification",
                        item.classification
                    )}

                    ${
                        item.indicators?.length
                            ? `
                                <div class="indicator-list">
                                    ${
                                        item.indicators
                                            .map(
                                                x =>
                                                    `• ${escapeHtml(x)}`
                                            )
                                            .join("<br>")
                                    }
                                </div>
                              `
                            : ""
                    }

                </div>
            `;
        }
    );
}


// =====================================================
// STEP 34 — Content Intelligence
// =====================================================

function displayContentIntelligence(
    content
) {

    const section =
        createDynamicSection(
            "contentSection",
            "🧠 Phishing Content Intelligence"
        );

    if (!content) {

        section.innerHTML +=
            '<div class="empty-intelligence">No content intelligence available.</div>';

        return;
    }

    const categories =
        content.categories || {};

    section.innerHTML += `

        <div class="intelligence-grid">

            ${infoCard(
                "Content Risk",
                content.score
            )}

            ${infoCard(
                "Classification",
                content.classification
            )}

            ${infoCard(
                "Urgency Signals",
                (categories.urgency || []).length
            )}

            ${infoCard(
                "Credential Signals",
                (categories.credentials || []).length
            )}

            ${infoCard(
                "Financial Signals",
                (categories.financial || []).length
            )}

            ${infoCard(
                "Threat Signals",
                (categories.threats || []).length
            )}

        </div>
    `;

    if (
        content.indicators &&
        content.indicators.length
    ) {

        section.innerHTML += `
            <div class="indicator-list">

                <strong>Detected Content Signals</strong>

                <br><br>

                ${
                    content.indicators
                        .map(
                            x =>
                                `• ${escapeHtml(x)}`
                        )
                        .join("<br>")
                }

            </div>
        `;
    }
}


// =====================================================
// STEP 37 — Correlation
// =====================================================

function displayCorrelation(
    correlation
) {

    const section =
        createDynamicSection(
            "correlationSection",
            "🔗 URL + Domain Correlation"
        );

    if (!correlation) {

        section.innerHTML +=
            '<div class="empty-intelligence">No correlation data available.</div>';

        return;
    }

    section.innerHTML += `

        <div class="intelligence-grid">

            ${infoCard(
                "Correlation Score",
                correlation.score
            )}

            ${infoCard(
                "Classification",
                correlation.classification
            )}

            ${infoCard(
                "Combined URL/DNS Risk",
                correlation.combined_url_domain_risk
            )}

            ${infoCard(
                "URLs",
                correlation.url_count
            )}

            ${infoCard(
                "Domains",
                correlation.domain_count
            )}

        </div>
    `;

    if (
        correlation.indicators?.length
    ) {

        section.innerHTML += `
            <div class="indicator-list">

                <strong>Correlation Evidence</strong>

                <br><br>

                ${
                    correlation.indicators
                        .map(
                            x =>
                                `• ${escapeHtml(x)}`
                        )
                        .join("<br>")
                }

            </div>
        `;
    }
}


// =====================================================
// STEP 39 — Forensic Report Summary
// =====================================================

function displayForensicSummary(
    report
) {

    const section =
        createDynamicSection(
            "reportSection",
            "📄 Forensic Investigation Report"
        );

    if (!report) {

        section.innerHTML +=
            '<div class="empty-intelligence">No forensic report available.</div>';

        return;
    }

    const summary =
        report.case_summary || {};

    const identity =
        report.email_identity || {};

    section.innerHTML += `

        <div class="intelligence-grid">

            ${infoCard(
                "Case Classification",
                summary.classification
            )}

            ${infoCard(
                "Threat Score",
                summary.threat_score
            )}

            ${infoCard(
                "Sender",
                identity.sender
            )}

            ${infoCard(
                "Subject",
                identity.subject
            )}

        </div>

        <div class="report-actions">

            <button
                id="downloadJsonButton"
                class="report-button"
            >
                ⬇ Export JSON Report
            </button>

        </div>
    `;
}


// =====================================================
// JSON Report Export
// =====================================================

function setupReportExport(
    report
) {

    const button =
        document.getElementById(
            "downloadJsonButton"
        );

    if (!button) return;

    button.onclick = function () {

        const json =
            JSON.stringify(
                report,
                null,
                2
            );

        const blob =
            new Blob(
                [json],
                {
                    type:
                        "application/json"
                }
            );

        const url =
            URL.createObjectURL(
                blob
            );

        const link =
            document.createElement("a");

        link.href = url;

        link.download =
            "email_forensic_report.json";

        document.body.appendChild(
            link
        );

        link.click();

        link.remove();

        URL.revokeObjectURL(
            url
        );
    };
}


// =====================================================
// Dynamic Sections
// =====================================================

function createDynamicSection(
    id,
    title
) {

    let section =
        document.getElementById(id);

    if (!section) {

        section =
            document.createElement("div");

        section.id = id;

        section.className =
            "analysis-section dynamic-intelligence";

        const heading =
            document.createElement("h3");

        heading.textContent =
            title;

        section.appendChild(
            heading
        );

        results.appendChild(
            section
        );
    }

    // Keep heading and clear old content
    const heading =
        section.querySelector("h3");

    section.innerHTML = "";

    if (heading) {

        section.appendChild(
            heading
        );

    } else {

        const newHeading =
            document.createElement("h3");

        newHeading.textContent =
            title;

        section.appendChild(
            newHeading
        );
    }

    return section;
}


// =====================================================
// UI Helpers
// =====================================================

function infoCard(
    title,
    value
) {

    return `
        <div class="intelligence-card">

            <span class="card-label">
                ${escapeHtml(title)}
            </span>

            <strong class="card-value">
                ${escapeHtml(
                    value ?? "--"
                )}
            </strong>

        </div>
    `;
}


function infoLine(
    title,
    value
) {

    return `
        <div class="info-line">

            <span>
                ${escapeHtml(title)}
            </span>

            <strong>
                ${escapeHtml(
                    value ?? "--"
                )}
            </strong>

        </div>
    `;
}


// =====================================================
// HTML Safety
// =====================================================

function escapeHtml(value) {

    return String(value)
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );
}
function displayThreatSummary(
    analysis,
    email
) {

    const section =
        createDynamicSection(
            "threatSummarySection",
            "🚨 Threat Summary"
        );

    const score =
        analysis.threat_score || 0;

    const classification =
        analysis.classification || "UNKNOWN";

    const indicators =
        analysis.indicators || [];

    let severityText =
        "No significant threat evidence detected.";

    if (score >= 60) {

        severityText =
            "Multiple independent security signals indicate that this email is highly likely to be malicious.";

    } else if (score >= 30) {

        severityText =
            "Several suspicious signals were detected and the email requires further investigation.";

    }

    section.innerHTML += `

        <div class="threat-summary">

            <div class="threat-summary-score">
                <span>Threat Score</span>
                <strong>${score}/100</strong>
            </div>

            <div class="threat-summary-status">
                <span>Classification</span>
                <strong>
                    ${escapeHtml(classification)}
                </strong>
            </div>

            <div class="threat-summary-text">
                ${escapeHtml(severityText)}
            </div>

        </div>

        <div class="evidence-chain">

            <h4>Why was this email flagged?</h4>

            <div class="evidence-flow">

                <div>🔐 Authentication Failure</div>
                <span>→</span>

                <div>📨 Header Mismatch</div>
                <span>→</span>

                <div>📎 Malicious Attachment</div>
                <span>→</span>

                <div>🧠 Phishing Language</div>

            </div>

        </div>
    `;
}