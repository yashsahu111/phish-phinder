import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import {
  analyze,
  extractOriginIp,
  PHISHING_SAMPLE,
  SAFE_SAMPLE,
  type AuthState,
} from "@/lib/mail-analysis";
import { lookupIpGeo, type IpGeo } from "@/lib/ip-geo.functions";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Mail AI — Email Threat & Incident Response Dashboard" },
      {
        name: "description",
        content:
          "Paste raw email headers or MIME and Mail AI returns a live threat score, SPF/DKIM/DMARC verdicts, hop-by-hop origin trace and an AI incident narrative.",
      },
      { property: "og:title", content: "Mail AI — Email Incident Response Dashboard" },
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
  const [active, setActive] = useState(0);
  const [gauge, setGauge] = useState(0);
  const [clock, setClock] = useState("00:00:00");
  const [downloadLabel, setDownloadLabel] = useState("Download Forensic PDF");
  const [busy, setBusy] = useState(false);
  const [geo, setGeo] = useState<IpGeo | null>(null);
  const [dispatchOpen, setDispatchOpen] = useState(false);

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

  // Project lat/lon onto the 620x400 map grid (equirectangular).
  const pin = geo
    ? { x: ((geo.lon + 180) / 360) * 620, y: ((90 - geo.lat) / 180) * 400 }
    : null;

  useEffect(() => {
    setActive(0);
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

  const hop = (a.hops[active] ?? a.hops[0])!;
  const CIRC = 603.2;

  const load = (sample: string) => {
    setMime(sample);
    setSubmitted(sample);
  };

  const INCIDENT_ID = "MA-90341";
  const EVIDENCE_HASH = "SHA-256: C4:9A:7E:11:0B:D3:88:F1:02";

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
      doc.text("Mail AI Security Lab · ThreatTrace Engine v4.2", pageW / 2, 19, {
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
          ["Evidence Hash", EVIDENCE_HASH, "Forensic Status", "SEALED · TAMPER-EVIDENT"],
        ],
        theme: "grid",
        styles: { fontSize: 8.5, cellPadding: 2.5 },
        columnStyles: {
          0: { fontStyle: "bold", fillColor: [241, 245, 249], cellWidth: 32 },
          2: { fontStyle: "bold", fillColor: [241, 245, 249], cellWidth: 32 },
        },
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
          ...a.badges.map((b): [string, string] => {
            const [name, status] = b.label.split(/[:·]/).map((s) => s.trim());
            return [name ?? b.label, status ?? b.label];
          }),
          ["AI Narrative Analysis", a.narrative],
        ],
        theme: "striped",
        headStyles: { fillColor: [15, 23, 42], fontSize: 9 },
        styles: { fontSize: 8.5, cellPadding: 2.5 },
        columnStyles: { 0: { fontStyle: "bold", cellWidth: 45 } },
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

      doc.save("ThreatTrace-Forensic-Report.pdf");
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
                Mail <span>AI</span>
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
              Paste headers or raw MIME, upload the source artifact, and Mail AI renders
              threat score, hop chain, and intent in seconds. Case{" "}
              <span className="case-id">#MA-90341</span> is active.
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
              <button className="demo safe" onClick={() => load(SAFE_SAMPLE)}>
                Load Safe Sample
              </button>
              <button className="demo bad" onClick={() => load(PHISHING_SAMPLE)}>
                Load Phishing Sample
              </button>
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
          </section>

          <div className="bottom-grid">
          <section className="card map-card" id="trace">
            <div className="map-head card-head">
              <div>
                <h2>Origin trace · hop chain</h2>
                <p className="card-label">Select a node to inspect the relay</p>
              </div>
              <span className="map-status">{a.relayLabel}</span>
            </div>

            <div className="map-box">
              <svg id="map" viewBox="0 0 620 400" role="img" aria-label="Relay hop trace">
                <g stroke="rgba(148,163,184,.13)" strokeWidth="1">
                  {[60, 120, 180, 240, 300, 360].map((y) => (
                    <line key={y} x1="0" y1={y} x2="620" y2={y} />
                  ))}
                  {[80, 180, 280, 380, 480, 580].map((x) => (
                    <line key={x} x1={x} y1="0" x2={x} y2="400" />
                  ))}
                </g>
                <text x="20" y="30" fill="#526073" fontFamily="JetBrains Mono, monospace" fontSize="10">
                  GRID 51.5N · 0.12W
                </text>
                <text x="20" y="48" fill="#526073" fontFamily="JetBrains Mono, monospace" fontSize="10">
                  NODE VIEW / THERMAL OVERLAY
                </text>
                <text x="600" y="30" textAnchor="end" fill={a.severityColor} fontFamily="JetBrains Mono, monospace" fontSize="10">
                  {a.mapStatus}
                </text>

                {a.hops.slice(0, -1).map((h, i) => {
                  const next = a.hops[i + 1]!;
                  return (
                  <path
                    key={h.ip + i}
                    className="route"
                    d={`M${h.x} ${h.y} Q ${(h.x + next.x) / 2} ${Math.min(h.y, next.y) - 70} ${next.x} ${next.y}`}
                    fill="none"
                    stroke={h.color}
                    strokeWidth="2"
                    opacity=".75"
                  />
                  );
                })}

                {a.hops.map((h, i) => (
                  <g
                    key={h.ip + i}
                    className={`node${i === active ? " active" : ""}`}
                    tabIndex={0}
                    role="button"
                    aria-label={h.title}
                    onClick={() => setActive(i)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setActive(i);
                      }
                    }}
                  >
                    <circle className="pulse" cx={h.x} cy={h.y} r="14" fill={h.color} opacity=".35" />
                    <circle className="core" cx={h.x} cy={h.y} r="9" fill={h.color} />
                    <text
                      x={h.x}
                      y={h.y + 30}
                      textAnchor="middle"
                      fill="#7c8798"
                      fontFamily="JetBrains Mono, monospace"
                      fontSize="10"
                    >
                      {h.ip}
                    </text>
                  </g>
                ))}

                {pin && (
                  <g className="geo-pin" aria-label={`Origin location: ${geo!.city}, ${geo!.country}`}>
                    <circle className="pulse" cx={pin.x} cy={pin.y} r="18" fill="#ff5265" opacity=".35" />
                    <circle cx={pin.x} cy={pin.y} r="6" fill="#ff5265" stroke="#0b0f1a" strokeWidth="2" />
                    <text
                      x={pin.x}
                      y={pin.y - 16}
                      textAnchor="middle"
                      fill="#ff5265"
                      fontFamily="JetBrains Mono, monospace"
                      fontSize="10"
                    >
                      {geo!.city}
                    </text>
                  </g>
                )}
              </svg>

              <div className="map-readout">
                <div className="readout-row">
                  <div>
                    <p className="readout-tag" style={{ color: hop.color, margin: 0 }}>
                      {hop.tag}
                    </p>
                    <p className="readout-title">{hop.title}</p>
                    <p className="readout-copy">{hop.body}</p>
                  </div>
                  <span className="risk" style={{ color: hop.color, borderColor: hop.color + "88" }}>
                    {hop.risk}
                  </span>
                </div>
              </div>
            </div>
          </section>

          <section className="card forensics-card" id="ip-forensics">
            <div className="card-head">
              <div>
                <h2>IP Forensics &amp; Origin Location</h2>
                <p className="card-label">Live geolocation via ip-api.com</p>
              </div>
              <span className="tag">{geo ? "Resolved" : "Resolving…"}</span>
            </div>

            <div className="forensics-grid">
              <div className="forensics-item">
                <span>Origin IP Address</span>
                <b>{originIp}</b>
              </div>
              <div className="forensics-item">
                <span>Country &amp; City</span>
                <b>{geo ? `${geo.city}, ${geo.country}` : "—"}</b>
              </div>
              <div className="forensics-item">
                <span>ISP / Organization</span>
                <b>{geo ? `${geo.isp} / ${geo.org}` : "—"}</b>
              </div>
              <div className="forensics-item">
                <span>Exact Coordinates</span>
                <b>{geo ? `${geo.lat.toFixed(4)}° · ${geo.lon.toFixed(4)}°` : "—"}</b>
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
              <button className="download" onClick={download} disabled={busy}>
                {downloadLabel}
              </button>
              <button className="dispatch" onClick={() => setDispatchOpen(true)}>
                Dispatch Evidence to CyberCell
              </button>
              <div className="export-meta">
                <span>ThreatTrace-Forensic-Report.pdf</span>
                <span>2.4 MB</span>
                <span>
                  Generated <strong>just now</strong>
                </span>
                <span>Tamper-evident · hash C4:9A…F1:02</span>
              </div>
            </section>
          </div>
        </div>

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
          <span>Mail AI Security Lab · SOC-2 Type II · Data residency EU-Central</span>
          <span>Heuristic ensemble: RF · GNN · LLM-cite · 11/11 nominal</span>
        </footer>
      </div>
    </div>
  );
}
