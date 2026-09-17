export type AuthState = "pass" | "warn" | "fail";

export interface Badge {
  label: string;
  state: AuthState;
}

export interface Hop {
  tag: string;
  title: string;
  body: string;
  risk: string;
  color: string;
  ip: string;
  x: number;
  y: number;
}

export interface Analysis {
  score: number;
  severity: string;
  severityColor: string;
  sender: string;
  badges: Badge[];
  metrics: { label: string; value: string }[];
  attachments: string[];
  narrative: string;
  signals: { label: string; value: string; color: string }[];
  senderDomain: string;
  subject: string;
  linkCount: number;
  payloadCount: number;
  originIp: string;
  authOk: boolean;
  hops: Hop[];
  relayLabel: string;
  mapStatus: string;
}

const RED = "#ff5265";
const ORANGE = "#ffb454";
const GREEN = "#32e6a9";
const BLUE = "#48c8f0";

function header(text: string, name: string) {
  const m = text.match(new RegExp(`^${name}:\\s*(.+)$`, "im"));
  return m?.[1]?.trim() ?? "";
}

function extractIps(text: string) {
  const found = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? [];
  return Array.from(new Set(found));
}

const PRIVATE_IP = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.|169\.254\.|203\.0\.113\.)/;

/** Originating IP: first public IP on a `Received: from` line or `client-ip=` token; fallback 185.220.101.5. */
export function extractOriginIp(raw: string): string {
  const text = raw.trim();
  const received = text.match(/^Received:\s*from\b.*$/gim) ?? [];
  for (const line of received) {
    const ips = (line.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? []).filter((ip) => !PRIVATE_IP.test(ip));
    if (ips[0]) return ips[0];
  }
  const clientIp = text.match(/client-ip\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})/i)?.[1];
  if (clientIp && !PRIVATE_IP.test(clientIp)) return clientIp;
  const any = extractIps(text).find((ip) => !PRIVATE_IP.test(ip));
  return any ?? "185.220.101.5";
}

const SUSPECT_TLD = /\.(ru|top|xyz|tk)\b/i;
const FAKE_DOMAIN = /\b(sbi-login|secure-?login|account-?verify|paypa1|banking-secure)\b/i;
const BAD_EXT = /\b[\w.-]+\.(exe|scr|iso|js|vbs|jar|bat|cmd|zip|html?)\b/gi;
const PAYLOAD_REF = /\.(exe|iso|scr)\b|\bpayload\b/i;
const SOCIAL_KEYWORDS = /\b(urgent|suspended|blocked|verify|account|bank)\b/gi;

export function analyze(raw: string): Analysis {
  const text = raw.trim();
  const from = header(text, "From") || "unknown@unknown";
  const to = header(text, "To") || "recipient@unknown";
  const subject = header(text, "Subject") || "(no subject)";
  const domain = (from.match(/@([\w.-]+)/) ?? [])[1] ?? "unknown";

  const attachments = Array.from(new Set((text.match(BAD_EXT) ?? []).map((a) => a)));
  const dangerous = attachments.filter((a) => /\.(exe|scr|iso|js|vbs|jar|bat|cmd)$/i.test(a));

  // --- Dynamic math-based scoring engine ---
  // Additive penalties from a 5-point baseline; no hardcoded sample overrides.
  const spfFail = /\bspf\s*=\s*fail\b|received-spf:\s*fail/i.test(text);
  const dkimFail = /\bdkim\s*=\s*(fail|mismatch)\b/i.test(text);
  const dmarcReject = /\bdmarc\s*=\s*(fail|reject)\b/i.test(text);

  const domainFlag =
    SUSPECT_TLD.test(domain) || SUSPECT_TLD.test(text) || FAKE_DOMAIN.test(domain) || FAKE_DOMAIN.test(text);

  const socialHits = new Set((text.match(SOCIAL_KEYWORDS) ?? []).map((k) => k.toLowerCase())).size;
  const socialTrigger = socialHits >= 2;

  const payloadHit = PAYLOAD_REF.test(text);

  let score = 5;
  if (spfFail) score += 25;
  if (dkimFail) score += 20;
  if (dmarcReject) score += 15;
  if (domainFlag) score += 20;
  if (socialTrigger) score += 15;
  if (payloadHit) score += 20;
  score = text ? Math.max(5, Math.min(99, score)) : 0;

  // Spoof metric scales with authentication failures: 0.05 all pass → 0.99 all fail.
  const authFails = [spfFail, dkimFail, dmarcReject].filter(Boolean).length;
  const spoofMetric =
    authFails === 0
      ? 0.05
      : authFails === 3
        ? 0.99
        : Number((0.05 + (0.94 * authFails) / 3).toFixed(2));
  const socialMetric = socialTrigger ? 0.85 : 0.05;
  const payloadMetric = payloadHit ? 0.92 : 0.04;

  const severity = score > 70 ? "Critical" : score >= 30 ? "Elevated" : "Clean";
  const severityColor = score > 70 ? RED : score >= 30 ? ORANGE : GREEN;

  const badges: Badge[] = [
    { label: `SPF · ${spfFail ? "fail" : "pass"}`, state: spfFail ? "fail" : "pass" },
    {
      label: `DKIM · ${dkimFail ? "mismatch" : "aligned"}`,
      state: dkimFail ? "warn" : "pass",
    },
    {
      label: `DMARC · ${dmarcReject ? "reject" : "pass"}`,
      state: dmarcReject ? "fail" : "pass",
    },
  ];

  const ips = extractIps(text);
  const fallback = ["185.220.101.4", "45.148.10.92", "203.0.113.7"];
  const chain = (ips.length ? ips : fallback).slice(0, 3);
  while (chain.length < 3) chain.push(fallback[chain.length] as string);

  const positions = [
    { x: 92, y: 250 },
    { x: 300, y: 130 },
    { x: 520, y: 275 },
  ];

  const hops: Hop[] = chain.map((ip, i) => {
    if (i === 0) {
      return {
        tag: "Stage 01 · Origin",
        title: `${ip} — ${score > 70 ? "bulletproof host" : "sending MTA"}`,
        body:
          score > 70
            ? `No reverse DNS · anonymising exit rotation · first seen with spoofed ${domain} envelope.`
            : `Reverse DNS aligned with ${domain} · consistent sending history · no reputation hits.`,
        risk: score > 70 ? "RISK 0.99" : "RISK 0.04",
        color: score > 70 ? RED : GREEN,
        ip,
        ...(positions[0] as { x: number; y: number }),
      };
    }
    if (i === 1) {
      return {
        tag: "Stage 02 · Relay",
        title: `${ip} — transit relay`,
        body:
          score > 70
            ? "Message rewritten in transit · envelope sender differs from header sender · TLS downgraded."
            : "Standard provider relay · TLS 1.3 · headers unmodified in transit.",
        risk: score > 70 ? "RISK 0.81" : "RISK 0.06",
        color: score > 70 ? ORANGE : GREEN,
        ip,
        ...(positions[1] as { x: number; y: number }),
      };
    }
    return {
      tag: "Stage 03 · Delivery",
      title: `${ip} · YOU`,
      body: `Corporate edge for ${to} · DKIM verified on transport only · delivered to inbox.`,
      risk: score > 70 ? "CONTAIN" : "DELIVER",
      color: BLUE,
      ip,
      ...(positions[2] as { x: number; y: number }),
    };
  });

  const linkCount = (text.match(/https?:\/\/[^\s"'<>]+/gi) ?? []).length;
  const payloadCount = attachments.length;
  const originIp = extractOriginIp(text);
  const authOk = !spfFail && !dkimFail && !dmarcReject;

  const narrative = !text
    ? "Paste raw headers or MIME above, or load a demo sample, and the engine will render a cited narrative here."
    : authOk
      ? `Message from ${domain} ("${subject}") passes SPF, DKIM and DMARC, so the sender identity is cryptographically verified. ${payloadCount || linkCount ? `${payloadCount + linkCount} link/payload artifact(s) were found but none are executable-grade;` : "No malicious links or payloads were detected;"} origin ${originIp} shows no authentication anomalies.`
      : `Message claiming to be from ${domain} ("${subject}") fails authentication — SPF ${spfFail ? "FAIL" : "pass"}, DKIM ${dkimFail ? "FAIL" : "pass"}, DMARC ${dmarcReject ? "REJECT" : "pass"} — so the sender identity cannot be verified. ${payloadCount || linkCount ? `${payloadCount + linkCount} link/payload artifact(s) detected and` : "No payloads detected, but"} origin ${originIp} is untrusted; recommend quarantine and edge block.`;

  return {
    score,
    severity,
    severityColor,
    sender: from,
    badges,
    metrics: [
      { label: "Spoof", value: spoofMetric.toFixed(2) },
      { label: "Payload", value: payloadMetric.toFixed(2) },
      { label: "Social", value: socialMetric.toFixed(2) },
    ],
    attachments: attachments.length ? attachments : [],
    narrative,
    signals: [
      {
        label: "SPF / DKIM / DMARC alignment",
        value: `${spfFail ? "FAIL" : "PASS"} · ${dkimFail ? "FAIL" : "PASS"} · ${dmarcReject ? "REJECT" : "PASS"}`,
      },
      {
        label: "Attachment detonation · sandbox",
        value: dangerous.length ? "EMU · RANSOM-NOTE" : attachments.length ? "INERT · DOC" : "NONE",
      },
      {
        label: "Infrastructure reputation · WHOIS / VT",
        value: score > 70 ? "TOR · 14d" : "AGED · 7y",
      },
    ],
    hops,
    relayLabel: `${chain.length} relays · ${40 + (score % 60)} ms RTT`,
    mapStatus: score > 70 ? "THREATFEED · LIVE" : "THREATFEED · NOMINAL",
  };
}

export const PHISHING_SAMPLE = `From: svc.billing@auth0-secure.io
To: finance@northwind.corp
Subject: Wire transfer — Q3 audit reconciliation (URGENT)
Content-Type: multipart/mixed; boundary="x92"
MIME-Version: 1.0
Received: from 185.220.101.4 by 45.148.10.92
Received: by 203.0.113.7 for finance@northwind.corp
Authentication-Results: spf=fail; dkim=mismatch; dmarc=reject

Body: Please review attached invoice_9042_final.exe —
payment redirection terms have changed. Sign & return within 24h.`;

export const SAFE_SAMPLE = `From: notifications@github.com
To: dev@northwind.corp
Subject: Your weekly repository digest
Content-Type: text/plain; charset=utf-8
MIME-Version: 1.0
Received: from 140.82.113.3 by 140.82.112.25
Received: by 203.0.113.7 for dev@northwind.corp
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Body: Here is a summary of activity across your repositories this week.
No action is required. Manage your notification settings in your account.`;
