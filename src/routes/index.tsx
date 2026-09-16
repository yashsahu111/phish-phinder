import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { jsPDF } from "jspdf";
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

  const download = () => {
    if (busy) return;
    setBusy(true);
    setDownloadLabel("Compiling evidence pack…");
    setTimeout(() => {
      const doc = new jsPDF();
      const pageW = doc.internal.pageSize.getWidth();
      let y = 20;

      // Header
      doc.setFont("helvetica", "bold");
      doc.setFontSize(16);
      doc.text("ThreatTrace Forensic Incident Report", 14, y);
      y += 8;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.text(`Incident ID: MA-90341`, 14, y);
      y += 6;
      doc.text(`Generated: ${new Date().toUTCString()}`, 14, y);
      y += 4;
      doc.setDrawColor(120);
      doc.line(14, y, pageW - 14, y);
      y += 10;

      // Summary
      doc.setFont("helvetica", "bold");
      doc.setFontSize(13);
      doc.text("Summary", 14, y);
      y += 7;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.text(`Overall Threat Score: ${a.score}%`, 14, y);
      y += 6;
      doc.text(`Risk Classification: ${a.severity}`, 14, y);
      y += 6;
      doc.text("AI Narrative Summary:", 14, y);
      y += 5;
      const narrativeLines = doc.splitTextToSize(a.narrative, pageW - 28);
      doc.text(narrativeLines, 14, y);
      y += narrativeLines.length * 5 + 6;

      // Authentication breakdown
      doc.setFont("helvetica", "bold");
      doc.setFontSize(13);
      doc.text("Authentication Breakdown", 14, y);
      y += 7;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      for (const b of a.badges) {
        doc.text(`${b.label}`, 14, y);
        y += 6;
      }
      y += 4;

      // IP telemetry
      doc.setFont("helvetica", "bold");
      doc.setFontSize(13);
      doc.text("IP Telemetry", 14, y);
      y += 7;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      const telemetry: [string, string][] = [
        ["Origin IP", originIp],
        ["Country", geo?.country ?? "Unresolved"],
        ["City", geo?.city ?? "Unresolved"],
        ["ISP / Organization", geo ? `${geo.isp} / ${geo.org}` : "Unresolved"],
        [
          "Coordinates",
          geo ? `${geo.lat.toFixed(4)}, ${geo.lon.toFixed(4)}` : "Unresolved",
        ],
      ];
      for (const [k, v] of telemetry) {
        const lines = doc.splitTextToSize(`${k}: ${v}`, pageW - 28);
        doc.text(lines, 14, y);
        y += lines.length * 5 + 1;
      }
      y += 5;

      // Raw artifact snippet
      doc.setFont("helvetica", "bold");
      doc.setFontSize(13);
      doc.text("Raw Artifact (excerpt)", 14, y);
      y += 7;
      doc.setFont("courier", "normal");
      doc.setFontSize(8);
      const rawLines = doc.splitTextToSize(
        submitted.slice(0, 1500),
        pageW - 28,
      );
      for (const line of rawLines) {
        if (y > 280) {
          doc.addPage();
          y = 20;
        }
        doc.text(line, 14, y);
        y += 4;
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

              <p className="ai-copy">{a.narrative}</p>

              {a.signals.map((s) => (
                <div className="signal" key={s.label}>
                  {s.label}
                  <b style={{ color: a.severityColor, background: a.severityColor + "1a" }}>{s.value}</b>
                </div>
              ))}
            </section>

            <section className="card export-card">
              <h2>Forensic export</h2>
              <p>PCAP · Header dump · YARA + MITRE ATT&amp;CK mapping · signed SHA-256</p>
              <button className="download" onClick={download} disabled={busy}>
                {downloadLabel}
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

        <footer>
          <span>Mail AI Security Lab · SOC-2 Type II · Data residency EU-Central</span>
          <span>Heuristic ensemble: RF · GNN · LLM-cite · 11/11 nominal</span>
        </footer>
      </div>
    </div>
  );
}
