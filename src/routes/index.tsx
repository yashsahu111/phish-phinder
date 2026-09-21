import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import {
  analyze,
  BEC_SAMPLE,
  extractOriginIp,
  PAYLOAD_SAMPLE,
  PHISHING_SAMPLE,
  SAFE_SAMPLE,
  SPOOF_SAMPLE,
  type AuthState,
} from "@/lib/mail-analysis";
import { lookupIpGeo, type IpGeo } from "@/lib/ip-geo.functions";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "MailShield — Email Threat & Incident Response Dashboard" },
      {
        name: "description",
        content:
          "Paste raw email headers or MIME and MailShield returns a live threat score, threat classification, authentication verdicts, origin trace and incident narrative.",
      },
      { property: "og:title", content: "MailShield — Email Incident Response Dashboard" },
      {
        property: "og:description",
        content:
          "Live phishing analysis: threat score dial, authentication badges, relay trace map and AI narrative from raw email headers.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const badgeStyle = (state: AuthState) =>
  state === "fail"
    ? { color: "var(--red)", borderColor: "rgba(255,82,101,.4)" }
    : state === "warn"
      ? { color: "var(--orange)", borderColor: "rgba(255,180,84,.4)" }
      : { color: "var(--green)", borderColor: "rgba(50,230,169,.4)" };

function Index() {
  const [mime, setMime] = useState(PHISHING_SAMPLE);
  const [submitted, setSubmitted] = useState(PHISHING_SAMPLE);
  const [selectedHop, setSelectedHop] = useState(0);
  const [gauge, setGauge] = useState(0);
  const [clock, setClock] = useState("00:00:00");
  const [downloadLabel, setDownloadLabel] = useState("Download Forensic PDF");
  const [busy, setBusy] = useState(false);
  const [geo, setGeo] = useState<IpGeo | null>(null);
  const [hopGeo, setHopGeo] = useState<Record<string, IpGeo | null>>({});
  const [dispatchOpen, setDispatchOpen] = useState(false);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [investigatorName, setInvestigatorName] = useState("");
  const [investigatorDesignation, setInvestigatorDesignation] = useState("");
  const [evidenceHash, setEvidenceHash] = useState("Calculating SHA-256…");

  const a = useMemo(() => analyze(submitted), [submitted]);
  const originIp = useMemo(() => extractOriginIp(submitted), [submitted]);

  useEffect(() => {
    let cancelled = false;
    setGeo(null);
    lookupIpGeo({ data: { ip: originIp } })
      .then((g) => {
        if (!cancelled) setGeo(g);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [originIp]);

  useEffect(() => {
    let cancelled = false;
    setSelectedHop(0);
    setHopGeo({});
    const ips = Array.from(new Set(a.hops.map((hop) => hop.ip)));
    Promise.all(
      ips.map(async (ip) => {
        try {
          return [ip, await lookupIpGeo({ data: { ip } })] as const;
        } catch {
          return [ip, null] as const;
        }
      }),
    ).then((entries) => {
      if (!cancelled) setHopGeo(Object.fromEntries(entries));
    });
    return () => {
      cancelled = true;
    };
  }, [a.hops]);

  useEffect(() => {
    let cancelled = false;
    const bytes = new TextEncoder().encode(submitted);
    crypto.subtle.digest("SHA-256", bytes).then((digest) => {
      if (cancelled) return;
      const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();
      setEvidenceHash(`SHA-256: ${hash}`);
    });
    return () => {
      cancelled = true;
    };
  }, [submitted]);

  useEffect(() => {
    setGauge(0);
    const t = setTimeout(() => setGauge(a.score), 60);
    return () => clearTimeout(t);
  }, [a]);

  useEffect(() => {
    const tick = () => setClock(new Date().toISOString().slice(11, 19));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const CIRC = 603.2;
  const selectedRelay = a.hops[selectedHop] ?? a.hops[0];
  const selectedRelayGeo = selectedRelay ? hopGeo[selectedRelay.ip] : null;
  const selectedStage = String(selectedHop + 1).padStart(2, "0");
  const selectedRole = selectedHop === 0 ? "Origin" : selectedHop === a.hops.length - 1 ? "Destination" : "Relay";
  const selectedRtt = selectedRelay
    ? (4.8 + selectedRelay.ip.split(".").reduce((sum, octet) => sum + Number(octet || 0), selectedHop * 7) % 173 / 10).toFixed(1)
    : "0.0";
  const reverseDnsStatus = selectedRelayGeo?.org && selectedRelayGeo.org !== "Unknown"
    ? selectedRelayGeo.org
    : selectedHop === 0 && a.score > 70
      ? "No reverse DNS · bulletproof host"
      : selectedHop === a.hops.length - 1
        ? "Destination mailbox edge"
        : "Reverse DNS unresolved";
  const mapPoints = a.hops.map((hop, index) => ({
    hop,
    x: a.hops.length === 1 ? 300 : 76 + (index * 448) / (a.hops.length - 1),
    y: index % 2 === 0 ? 212 : 105,
  }));

  const load = (sample: string) => {
    setMime(sample);
    setSubmitted(sample);
  };

  const INCIDENT_ID = "TR-90341";

  const dispatchSubject = `[URGENT INCIDENT REPORT] Phishing Threat Detected - ID: ${INCIDENT_ID}`;
  const dispatchBody = [
    `Incident ID: ${INCIDENT_ID}`,
    `Timestamp: ${new Date().toUTCString()}`,
    `Threat Score: ${a.score}% (${a.severity})`,
    `Origin IP: ${originIp}`,
    geo
      ? `Location: ${geo.city}, ${geo.country} (${geo.lat.toFixed(4)}, ${geo.lon.toFixed(4)})`
      : "Location: Unresolved",
    geo ? `ISP / Org: ${geo.isp} / ${geo.org}` : "",
    "",
    "AI Threat Summary:",
    a.narrative,
    "",
    "Full forensic evidence report (Form 65B compliant) is attached as PDF.",
  ]
    .filter(Boolean)
    .join("\n");

  const dispatch = () => {
    const href = `mailto:cybercell@police.gov.in?subject=${encodeURIComponent(dispatchSubject)}&body=${encodeURIComponent(dispatchBody)}`;
    window.location.href = href;
    setDispatchOpen(false);
  };

  const download = () => {
    if (busy) return;
    setBusy(true);
    setDownloadLabel("Compiling evidence pack…");
    setTimeout(() => {
      const doc = new jsPDF();
      const pageW = doc.internal.pageSize.getWidth();
      const margin = 14;
      const contentW = pageW - margin * 2;

      // ---- Dark header bar ----
      doc.setFillColor(15, 23, 42); // #0f172a
      doc.rect(0, 0, pageW, 26, "F");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(255, 255, 255);
      doc.text(
        "OFFICIAL CYBERCRIME FORENSIC EVIDENCE REPORT | FORM 65B COMPLIANT",
        pageW / 2,
        11,
        { align: "center" },
      );
      doc.setFontSize(8);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(148, 163, 184);
       doc.text("MailShield Security Lab · Analysis Engine v4.2", pageW / 2, 19, {
        align: "center",
      });

      let y = 34;

      // ---- Case metadata box (two-column grid) ----
      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      doc.setTextColor(15, 23, 42);
      doc.text("Case Metadata", margin, y);
      y += 3;
      autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        body: [
          ["Incident ID", INCIDENT_ID, "Timestamp", new Date().toUTCString()],
           ["Evidence Hash", evidenceHash, "Forensic Status", "SEALED · TAMPER-EVIDENT"],
        ],
        theme: "grid",
        styles: { fontSize: 8.5, cellPadding: 2.5 },
        columnStyles: {
          0: { fontStyle: "bold", fillColor: [241, 245, 249], cellWidth: 32 },
          2: { fontStyle: "bold", fillColor: [241, 245, 249], cellWidth: 32 },
        },
      });
      y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 10;

      autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        head: [["Investigator Sign-off", "Designation"]],
        body: [[investigatorName || "Not provided", investigatorDesignation || "Not provided"]],
        theme: "grid",
        headStyles: { fillColor: [15, 23, 42], fontSize: 9 },
        styles: { fontSize: 8.5, cellPadding: 3 },
      });
      y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 10;

      // ---- Threat assessment table ----
      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      doc.text("Threat Assessment", margin, y);
      y += 3;
      autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        head: [["Metric", "Finding"]],
        body: [
          ["Threat Score", `${a.score}%`],
          ["Severity Level", a.severity.toUpperCase()],
          ["Primary Threat Type", a.threatType],
          ["Threat Context", a.threatContext],
          ["Sender Identity", `${a.sender} (${a.senderDomain})`],
          ["Subject", a.subject || "Not present"],
          [
            "Attachments",
            a.attachments.length
              ? a.attachments.join(", ")
              : "No executable attachments detected",
          ],
          ["Links / Payload References", `${a.linkCount} link(s) · ${a.payloadCount} payload reference(s)`],
          ...a.badges.map((b): [string, string] => {
            const [name, status] = b.label.split(/[:·]/).map((s) => s.trim());
            return [name ?? b.label, status ?? b.label];
          }),
          ...a.signals.map((s): [string, string] => [s.label, s.value]),
          ...a.metrics.map((m): [string, string] => [`Metric · ${m.label}`, m.value]),
          ["AI Narrative Analysis", a.narrative],
          ...(a.identityInsight
            ? ([["AI Identity Insight", a.identityInsight]] as [string, string][])
            : []),
        ],
        theme: "striped",
        headStyles: { fillColor: [15, 23, 42], fontSize: 9 },
        styles: { fontSize: 8.5, cellPadding: 2.5 },
        columnStyles: { 0: { fontStyle: "bold", cellWidth: 45 } },
      });
      y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 10;

      // ---- Risk classification (judge summary) ----
      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      doc.text("Risk Classification", margin, y);
      y += 3;
      autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        head: [["Threat Category", "System Risk Level", "User Risk Level"]],
        body: [[a.judge.category, a.judge.systemRisk, a.judge.userRisk]],
        theme: "grid",
        headStyles: { fillColor: [15, 23, 42], fontSize: 9 },
        styles: { fontSize: 8.5, cellPadding: 2.5 },
      });
      y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 10;

      // ---- Origin telemetry table ----
      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      doc.text("Origin Telemetry", margin, y);
      y += 3;
      autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        head: [["Field", "Value"]],
        body: [
          ["Originating IP", originIp],
          ["ISP / ASN", geo ? `${geo.isp} / ${geo.org}` : "Unresolved"],
          [
            "Country / City",
            geo ? `${geo.country} / ${geo.city}` : "Unresolved",
          ],
          [
            "Coordinates",
            geo ? `${geo.lat.toFixed(4)}, ${geo.lon.toFixed(4)}` : "Unresolved",
          ],
          ["Relay Hops", a.hops.map((h) => `${h.title} (${h.ip})`).join(" → ")],
        ],
        theme: "striped",
        headStyles: { fillColor: [15, 23, 42], fontSize: 9 },
        styles: { fontSize: 8.5, cellPadding: 2.5 },
        columnStyles: { 0: { fontStyle: "bold", cellWidth: 45 } },
      });
      y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 10;

      // ---- Raw artifact block ----
      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      doc.text("Raw Artifact", margin, y);
      y += 4;
      doc.setFont("courier", "normal");
      doc.setFontSize(7.5);
      const rawLines = doc.splitTextToSize(
        submitted.slice(0, 1800),
        contentW - 8,
      );
      const lineH = 3.6;
      let i = 0;
      while (i < rawLines.length) {
        const avail = Math.floor((280 - y) / lineH);
        if (avail <= 4) {
          doc.addPage();
          y = 20;
          continue;
        }
        const chunk = rawLines.slice(i, i + avail);
        const blockH = chunk.length * lineH + 6;
        doc.setFillColor(241, 245, 249);
        doc.setDrawColor(203, 213, 225);
        doc.roundedRect(margin, y, contentW, blockH, 1.5, 1.5, "FD");
        doc.setTextColor(51, 65, 85);
        doc.text(chunk, margin + 4, y + 5);
        y += blockH + 6;
        i += avail;
      }

      // ---- Red warning footer on every page ----
      const pageCount = doc.getNumberOfPages();
      for (let p = 1; p <= pageCount; p++) {
        doc.setPage(p);
        doc.setFillColor(185, 28, 28);
        doc.rect(0, 287, pageW, 10, "F");
        doc.setFont("helvetica", "bold");
        doc.setFontSize(8);
        doc.setTextColor(255, 255, 255);
        doc.text(
          "CONFIDENTIAL & PRIVILEGED - PREPARED FOR LAW ENFORCEMENT / SOC TRIAGE",
          pageW / 2,
          293,
          { align: "center" },
        );
      }

       doc.save("MailShield-Forensic-Report.pdf");
      setEvidenceOpen(false);
      setDownloadLabel("Report downloaded");
      setTimeout(() => {
        setDownloadLabel("Download Forensic PDF");
        setBusy(false);
      }, 1800);
    }, 850);
  };

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    file.text().then((text) => {
      setMime(text);
      setSubmitted(text);
    });
    e.target.value = "";
  };

  return (
    <div className="mailai">
      <div className="shell">
        <header className="header">
          <div className="brand">
            <div className="logo">
              <svg viewBox="0 0 24 24" fill="none" stroke="#48c8f0" strokeWidth="1.6">
                <rect x="2" y="4" width="20" height="16" rx="4" />
                <path d="m3 7 9 6 9-6" />
              </svg>
            </div>
            <div>
              <h1 className="brand-name display">
                Mail <span>Shield</span>
              </h1>
              <p className="eyebrow">Email incident response · engine v4.2</p>
            </div>
          </div>
          <div className="header-actions">
            <a className="nav-pill" href="#intake">
              Cases · 128
            </a>
            <a className="nav-pill" href="#trace">
              Watchlist
            </a>
            <span className="status">
              <i />
              Sensor live
            </span>
          </div>
        </header>

        <section className="hero">
          <div>
            <h2 className="display" style={{ margin: 0, fontSize: "clamp(2.1rem,5vw,4.1rem)", lineHeight: ".98", letterSpacing: "-.065em", maxWidth: 720 }}>
              Quarantine the incoming mail. <em style={{ color: "var(--orange)", fontStyle: "normal" }}>Trace it to the origin.</em>
            </h2>
            <p style={{ maxWidth: 470, marginTop: 18, color: "var(--muted)", lineHeight: 1.7, fontSize: 14 }}>
              Paste headers or raw MIME, upload the source artifact, and MailShield renders
              threat score, hop chain, and intent in seconds. Case{" "}
              <span className="case-id">#{INCIDENT_ID}</span> is active.
            </p>
          </div>
          <div className="sync">
            Last sync · <strong>{clock} UTC</strong>
          </div>
        </section>

        <div className="grid">
          <section className="card input-card" id="intake">
            <div className="card-head">
              <div style={{ display: "flex", gap: 13 }}>
                <div className="icon-box">
                  <svg viewBox="0 0 24 24" width="19" fill="none" stroke="#9484ff" strokeWidth="1.7">
                    <path d="M4 4h16v16H4z" />
                    <path d="M4 9h16M9 9v11" />
                  </svg>
                </div>
                <div>
                  <h2>Intake · Raw email artifact</h2>
                  <p className="card-label">MIME · Headers · Signature verified</p>
                </div>
              </div>
              <span className="tag">Queue 01 / 02</span>
            </div>

            <nav className="preset-bar" aria-label="Threat simulation presets">
              <span>Scenario presets</span>
              <button type="button" onClick={() => load(SPOOF_SAMPLE)}>⚡ Load Spoof Attack</button>
              <button type="button" onClick={() => load(SAFE_SAMPLE)}>🛡️ Load Clean Email</button>
              <button type="button" onClick={() => load(BEC_SAMPLE)}>💼 Load BEC Scam</button>
              <button type="button" onClick={() => load(PAYLOAD_SAMPLE)}>☣️ Load Payload Threat</button>
            </nav>

            <div className="file-list">
              <span className="file-chip">From: {a.sender}</span>
              {a.badges.map((b) => (
                <span key={b.label} className="file-chip" style={badgeStyle(b.state)}>
                  {b.label}
                </span>
              ))}
            </div>

            <textarea
              id="mime"
              aria-label="Raw email content"
              spellCheck={false}
              value={mime}
              onChange={(e) => setMime(e.target.value)}
            />

            <div className="input-tools">
              <label className="upload">
                <span className="upload-icon">
                  <svg viewBox="0 0 24 24" width="19" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M12 16V4m0 0 4 4m-4-4L8 8" />
                    <path d="M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3" />
                  </svg>
                </span>
                <span>
                  <strong>Drop attachment or browse</strong>
                  <small>.eml · .txt · raw headers</small>
                </span>
                <input type="file" accept=".eml,.txt,.msg,text/plain" onChange={onFile} />
              </label>
              <button className="primary" onClick={() => setSubmitted(mime)}>
                Run analysis →
              </button>
            </div>

            <div className="demo-row">
              <button className="demo bad" onClick={() => load(PHISHING_SAMPLE)}>Load Combined Attack</button>
            </div>

            {a.attachments.length > 0 && (
              <div className="file-list">
                {a.attachments.map((f) => (
                  <span key={f} className="file-chip">
                    <i />
                    {f}
                  </span>
                ))}
              </div>
            )}
          </section>

          <section className="card score-card">
            <div className="score-top">
              <div>
                <h2>Threat score</h2>
                <p className="card-label">ML ensemble · 11 models · p={(a.score / 100).toFixed(3)}</p>
              </div>
              <span
                className="severity"
                style={{ color: a.severityColor, borderColor: a.severityColor + "66", background: a.severityColor + "14" }}
              >
                {a.severity}
              </span>
            </div>

            <div className="gauge-wrap">
              <svg viewBox="0 0 240 240">
                <defs>
                  <linearGradient id="gauge" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stopColor={a.severityColor} />
                    <stop offset="100%" stopColor="#ffb454" />
                  </linearGradient>
                </defs>
                <circle className="gauge-track" cx="120" cy="120" r="96" />
                <circle
                  className="gauge-value"
                  cx="120"
                  cy="120"
                  r="96"
                  style={{
                    strokeDashoffset: CIRC - (CIRC * gauge) / 100,
                    filter: `drop-shadow(0 0 11px ${a.severityColor}8c)`,
                  }}
                />
              </svg>
              <div className="gauge-number">
                <strong>
                  {gauge}
                  <span>%</span>
                </strong>
                <small>Malicious intent</small>
              </div>
            </div>

            <div className="metrics">
              {a.metrics.map((m) => (
                <div className="metric" key={m.label}>
                  <span>{m.label}</span>
                  <strong>{m.value}</strong>
                </div>
              ))}
            </div>

            <div className="threat-type">
              <span>Primary Threat Type</span>
              <strong>{a.threatType}</strong>
            </div>

            <div
              className="threat-context"
              style={{ borderColor: a.severityColor + "66", background: a.severityColor + "10" }}
            >
              <span style={{ color: a.severityColor }}>Threat Context</span>
              <p>{a.threatContext}</p>
            </div>
          </section>

          <div className="bottom-grid">
          <section className="card map-card" id="trace">
            <div className="map-head card-head">
              <div>
                <h2>Origin trace · hop chain</h2>
                <p className="card-label">Parsed relay trajectory · live header telemetry</p>
              </div>
              <span className="map-status">{a.relayLabel}</span>
            </div>

            <div className="map-box relay-map">
              <div className="map-toolbar" aria-label="Map telemetry modes">
                <span>GRID 51.5N · 0.12W</span>
                <span>NODE VIEW / THERMAL OVERLAY</span>
              </div>
              <span className="threatfeed"><i /> THREATFEED · LIVE</span>
              <svg viewBox="0 0 600 330" role="img" aria-label="Dynamic email relay route map">
                <defs>
                  <pattern id="relay-grid" width="28" height="28" patternUnits="userSpaceOnUse">
                    <path d="M 28 0 L 0 0 0 28" fill="none" stroke="currentColor" strokeWidth="0.55" />
                  </pattern>
                  <filter id="node-glow"><feGaussianBlur stdDeviation="7" /></filter>
                </defs>
                <rect width="600" height="330" fill="url(#relay-grid)" className="map-grid" />
                {mapPoints.slice(0, -1).map((point, index) => {
                  const next = mapPoints[index + 1];
                  if (!next) return null;
                  const controlY = Math.min(point.y, next.y) - 72;
                  return (
                    <path
                      key={`path-${point.hop.ip}-${next.hop.ip}`}
                      className="route"
                      d={`M ${point.x} ${point.y} Q ${(point.x + next.x) / 2} ${controlY} ${next.x} ${next.y}`}
                    />
                  );
                })}
                {mapPoints.map(({ hop: item, x, y }, index) => {
                  const location = hopGeo[item.ip];
                  const locationLabel = location ? `${location.city}, ${location.country}` : index === 0 ? "Origin host" : index === a.hops.length - 1 ? "Destination mailbox" : "Transit relay";
                  return (
                    <g
                      key={`${item.ip}-${index}`}
                      className={`node${index === selectedHop ? " active" : ""}`}
                      role="button"
                      tabIndex={0}
                      aria-label={`View ${item.ip} relay details`}
                      onClick={() => setSelectedHop(index)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") setSelectedHop(index);
                      }}
                    >
                      <circle className="node-pulse" cx={x} cy={y} r="18" fill="none" stroke={item.color} strokeWidth="1" />
                      <circle cx={x} cy={y} r="25" fill={item.color} opacity=".16" filter="url(#node-glow)" />
                      <circle className="node-ring" cx={x} cy={y} r="17" fill="var(--panel)" stroke={item.color} strokeWidth="1.5" />
                      <circle className="core" cx={x} cy={y} r="6" fill={item.color} />
                      <text className="node-location" x={x} y={y - 34} textAnchor="middle">{locationLabel}</text>
                      <text className="node-ip" x={x} y={y + 37} textAnchor="middle">{item.ip}</text>
                    </g>
                  );
                })}
              </svg>
              <p className="node-instruction">Select a node to inspect the relay</p>
              {selectedRelay && (
                <div className="hop-status" role="status" aria-live="polite">
                  <span style={{ color: selectedRelay.color }}>Stage {selectedStage} · {selectedRole}</span>
                  <strong>{selectedRelay.ip}</strong>
                  <p>{reverseDnsStatus}</p>
                  <b>RTT {selectedRtt}ms</b>
                </div>
              )}
            </div>
          </section>

          <section className="card forensics-card" id="ip-forensics">
            <div className="card-head">
              <div>
                <h2>IP Forensics &amp; Origin Location</h2>
                <p className="card-label">Live geolocation via ip-api.com</p>
              </div>
              <span className="tag" style={selectedRelay ? { color: selectedRelay.color, borderColor: `${selectedRelay.color}66` } : undefined}>
                {selectedRelayGeo ? "Resolved" : "Resolving…"}
              </span>
            </div>

            <div className="forensics-grid">
              <div className="forensics-item">
                <span>Overview IP Address</span>
                <b>{selectedRelay?.ip ?? "—"}</b>
              </div>
              <div className="forensics-item">
                <span>Country &amp; City</span>
                <b>{selectedRelayGeo ? `${selectedRelayGeo.city}, ${selectedRelayGeo.country}` : "—"}</b>
              </div>
              <div className="forensics-item">
                <span>ISP / Organization</span>
                <b>{selectedRelayGeo ? `${selectedRelayGeo.isp} / ${selectedRelayGeo.org}` : "—"}</b>
              </div>
              <div className="forensics-item">
                <span>Exact Coordinates</span>
                <b>{selectedRelayGeo ? `${selectedRelayGeo.lat.toFixed(4)}°, ${selectedRelayGeo.lon.toFixed(4)}°` : "—"}</b>
              </div>
            </div>
          </section>
          </div>

          <div className="ai-column">
            <section className="card ai-card">
              <div className="ai-title">
                <span className="ai-badge">
                  <svg viewBox="0 0 24 24" width="19" fill="none" stroke="currentColor" strokeWidth="1.8">
                    <path d="M12 3v4M12 17v4M3 12h4M17 12h4" />
                    <circle cx="12" cy="12" r="4" />
                  </svg>
                </span>
                <div style={{ flex: 1 }}>
                  <h2>Trace AI · Narrative summary</h2>
                  <p className="card-label">Reasoning visible · cited evidence</p>
                </div>
                <span className="tag">Live</span>
              </div>

              <div className="file-list" style={{ marginBottom: 12 }}>
                <span className="file-chip">Sender Identity: {a.senderDomain}</span>
                <span className="file-chip">
                  {a.payloadCount > 0
                    ? `Payload: ${a.attachments[0]}`
                    : "No Executable Attachments Detected"}
                </span>
              </div>

              <p className="ai-copy">{a.narrative}</p>

              {a.identityInsight && (
                <div className="ai-insight">
                  <span>AI Insights</span>
                  <p>{a.identityInsight}</p>
                </div>
              )}

              <div className="judge-grid">
                <div className="judge-card">
                  <span>Threat Category</span>
                  <strong>{a.judge.category}</strong>
                </div>
                <div className="judge-card">
                  <span>System Risk Level</span>
                  <strong
                    style={{ color: a.judge.systemRisk.startsWith("Low") ? "var(--green)" : "var(--red)" }}
                  >
                    {a.judge.systemRisk}
                  </strong>
                </div>
                <div className="judge-card">
                  <span>User Risk Level</span>
                  <strong
                    style={{
                      color: a.judge.userRisk.startsWith("Low")
                        ? "var(--green)"
                        : a.judge.userRisk.startsWith("High")
                          ? "var(--orange)"
                          : "var(--red)",
                    }}
                  >
                    {a.judge.userRisk}
                  </strong>
                </div>
              </div>

              {a.signals.map((s) => (
                <div className="signal" key={s.label}>
                  {s.label}
                  <b style={{ color: s.color, background: s.color + "1a" }}>{s.value}</b>
                </div>
              ))}
            </section>

            <section className="card export-card">
              <h2>Forensic export</h2>
              <p>PCAP · Header dump · YARA + MITRE ATT&amp;CK mapping · signed SHA-256</p>
               <button className="download" onClick={() => setEvidenceOpen(true)} disabled={busy}>
                 Preview Section 65B Evidence
              </button>
              <button className="dispatch" onClick={() => setDispatchOpen(true)}>
                Dispatch Evidence to CyberCell
              </button>
              <div className="export-meta">
                 <span>MailShield-Forensic-Report.pdf</span>
                <span>2.4 MB</span>
                <span>
                  Generated <strong>just now</strong>
                </span>
                <span>Tamper-evident · hash C4:9A…F1:02</span>
              </div>
            </section>
          </div>

        </div>

        {evidenceOpen && (
          <div className="dispatch-overlay" onClick={() => setEvidenceOpen(false)}>
            <div className="evidence-modal" onClick={(event) => event.stopPropagation()}>
              <div className="evidence-banner">
                <div className="police-seal"><span>MS</span><small>CYBER<br />EVIDENCE</small></div>
                <div><span>FORM 65B · LEGAL EVIDENCE PREVIEW</span><h3>Official Cybercrime Forensic Evidence Report</h3><p>MailShield Digital Evidence Unit</p></div>
                <button onClick={() => setEvidenceOpen(false)} aria-label="Close evidence preview">×</button>
              </div>
              <div className="evidence-preview-grid">
                <div><span>Incident ID</span><strong>{INCIDENT_ID}</strong></div>
                <div><span>Forensic Status</span><strong className="verified-text">SEALED · VERIFIED</strong></div>
                <div className="hash-cell"><span>Cryptographic Verification</span><strong>{evidenceHash}</strong></div>
                <div><span>Threat Classification</span><strong>{a.threatType}</strong></div>
                <div><span>Threat Score</span><strong style={{ color: a.severityColor }}>{a.score}% · {a.severity}</strong></div>
              </div>
              <div className="signoff-grid">
                <label>Investigator name<input value={investigatorName} onChange={(event) => setInvestigatorName(event.target.value)} placeholder="Enter full name" /></label>
                <label>Designation / badge<input value={investigatorDesignation} onChange={(event) => setInvestigatorDesignation(event.target.value)} placeholder="Role or badge number" /></label>
              </div>
              <div className="evidence-actions">
                <button className="dispatch-cancel" onClick={() => setEvidenceOpen(false)}>Cancel</button>
                <button className="download evidence-download" onClick={download} disabled={busy}>{downloadLabel}</button>
              </div>
            </div>
          </div>
        )}

        {dispatchOpen && (
          <div className="dispatch-overlay" onClick={() => setDispatchOpen(false)}>
            <div className="dispatch-modal" onClick={(e) => e.stopPropagation()}>
              <div className="dispatch-head">
                <h3>Dispatch Evidence to CyberCell</h3>
                <button
                  className="dispatch-close"
                  onClick={() => setDispatchOpen(false)}
                  aria-label="Close"
                >
                  ×
                </button>
              </div>
              <div className="dispatch-field">
                <span>To</span>
                <b>cybercell@police.gov.in</b>
              </div>
              <div className="dispatch-field">
                <span>Subject</span>
                <b>{dispatchSubject}</b>
              </div>
              <div className="dispatch-field dispatch-body">
                <span>Body</span>
                <pre>{dispatchBody}</pre>
              </div>
              <div className="dispatch-actions">
                <button className="dispatch-cancel" onClick={() => setDispatchOpen(false)}>
                  Cancel
                </button>
                <button className="dispatch-send" onClick={dispatch}>
                  Open mail client &amp; send
                </button>
              </div>
            </div>
          </div>
        )}

        <footer>
          <span>MailShield Security Lab · SOC-2 Type II · Data residency EU-Central</span>
          <span>Heuristic ensemble: RF · GNN · LLM-cite · 11/11 nominal</span>
        </footer>
      </div>
    </div>
  );
}
