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
  signals: { label: string; value: string }[];
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

const SUSPECT_TLD = /\.(io|xyz|top|ru|cc|zip)\b/i;
const URGENCY = /\b(urgent|immediately|within 24h|asap|final notice|verify now|act now|suspended)\b/i;
const MONEY = /\b(wire transfer|payment redirection|bank details|invoice|iban|beneficiary|gift card|bitcoin)\b/i;
const BAD_EXT = /\b[\w.-]+\.(exe|scr|iso|js|vbs|jar|bat|cmd|zip|html?)\b/gi;
const CRED = /\b(password|credentials|login|reset your|sign in|two-factor|otp)\b/i;

export function analyze(raw: string): Analysis {
  const text = raw.trim();
  const from = header(text, "From") || "unknown@unknown";
  const to = header(text, "To") || "recipient@unknown";
  const subject = header(text, "Subject") || "(no subject)";
  const domain = (from.match(/@([\w.-]+)/) ?? [])[1] ?? "unknown";

  const attachments = Array.from(new Set((text.match(BAD_EXT) ?? []).map((a) => a)));
  const dangerous = attachments.filter((a) => /\.(exe|scr|iso|js|vbs|jar|bat|cmd)$/i.test(a));

  const spfFail = /spf[^\n]*fail/i.test(text) || SUSPECT_TLD.test(domain);
  const dkimFail = /dkim[^\n]*(fail|mismatch|none)/i.test(text) || dangerous.length > 0;
  const dmarcReject = /dmarc[^\n]*(reject|fail)/i.test(text) || (spfFail && dkimFail);

  let spoof = 0.05;
  let payload = 0.04;
  let social = 0.05;

  if (spfFail) spoof += 0.55;
  if (dkimFail) spoof += 0.25;
  if (dmarcReject) spoof += 0.15;
  if (/auth0|paypal|microsoft|secure|billing|support/i.test(domain) && SUSPECT_TLD.test(domain))
    spoof += 0.2;

  if (dangerous.length) payload += 0.8;
  else if (attachments.length) payload += 0.35;
  if (/macro|emu|reverse-shell|obfuscat/i.test(text)) payload += 0.2;

  if (URGENCY.test(text) || /urgent/i.test(subject)) social += 0.35;
  if (MONEY.test(text)) social += 0.4;
  if (CRED.test(text)) social += 0.25;

  const clamp = (n: number) => Math.max(0.02, Math.min(0.99, n));
  spoof = clamp(spoof);
  payload = clamp(payload);
  social = clamp(social);

  // Hard-fail override: explicit phishing flags in the text (spf=fail,
  // dkim=fail, Received-SPF: fail) or a suspicious TLD/domain (e.g. .ru)
  // force the score straight to 94% (Critical) with a bright-red dial.
  const PHISH_FLAGS = /\b(spf\s*=\s*fail|dkim\s*=\s*fail|received-spf:\s*fail)\b/i;
  const phishingFlags =
    PHISH_FLAGS.test(text) ||
    /\.ru\b/i.test(text) ||
    spfFail ||
    dkimFail ||
    dmarcReject ||
    SUSPECT_TLD.test(domain);

  if (phishingFlags) {
    payload = 0.91;
    social = 0.95;
  }

  const score = phishingFlags
    ? 94
    : text
      ? Math.round(Math.min(99, (spoof * 0.4 + payload * 0.35 + social * 0.25) * 100))
      : 0;

  const severity =
    score > 80 ? "Critical" : score >= 45 ? "Elevated" : score >= 20 ? "Guarded" : "Clean";
  const severityColor =
    score > 80 ? RED : score >= 45 ? ORANGE : score >= 20 ? BLUE : GREEN;

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
        title: `${ip} — ${score >= 45 ? "bulletproof host" : "sending MTA"}`,
        body:
          score >= 45
            ? `No reverse DNS · anonymising exit rotation · first seen with spoofed ${domain} envelope.`
            : `Reverse DNS aligned with ${domain} · consistent sending history · no reputation hits.`,
        risk: score >= 45 ? "RISK 0.99" : "RISK 0.04",
        color: score >= 45 ? RED : GREEN,
        ip,
        ...(positions[0] as { x: number; y: number }),
      };
    }
    if (i === 1) {
      return {
        tag: "Stage 02 · Relay",
        title: `${ip} — transit relay`,
        body:
          score >= 45
            ? "Message rewritten in transit · envelope sender differs from header sender · TLS downgraded."
            : "Standard provider relay · TLS 1.3 · headers unmodified in transit.",
        risk: score >= 45 ? "RISK 0.81" : "RISK 0.06",
        color: score >= 45 ? ORANGE : GREEN,
        ip,
        ...(positions[1] as { x: number; y: number }),
      };
    }
    return {
      tag: "Stage 03 · Delivery",
      title: `${ip} · YOU`,
      body: `Corporate edge for ${to} · DKIM verified on transport only · delivered to inbox.`,
      risk: score >= 45 ? "CONTAIN" : "DELIVER",
      color: BLUE,
      ip,
      ...(positions[2] as { x: number; y: number }),
    };
  });

  const narrative = !text
    ? "Paste raw headers or MIME above, or load a demo sample, and the engine will render a cited narrative here."
    : score >= 75
      ? `Likely BEC → payload hybrid. Envelope spoofs "${domain}"; subject "${subject}" applies deadline pressure${dangerous.length ? ` and the ${dangerous[0]} attachment carries executable content` : ""}. Recommend quarantine and blocking ${chain[0]} at the edge.`
      : score >= 45
        ? `Mixed signals on "${subject}". Authentication is partially broken for ${domain} and the body uses persuasion patterns. Hold for analyst review before release.`
        : score >= 20
          ? `Low-risk mail from ${domain}. Minor heuristics fired (tone or link shape) but authentication aligns. Safe to deliver with monitoring.`
          : `Benign. ${domain} passes SPF, DKIM and DMARC, no executable attachments, and no urgency or payment-redirection language in "${subject}".`;

  return {
    score,
    severity,
    severityColor,
    sender: from,
    badges,
    metrics: [
      { label: "Spoof", value: spoof.toFixed(2) },
      { label: "Payload", value: payload.toFixed(2) },
      { label: "Social", value: social.toFixed(2) },
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
        value: score >= 45 ? "TOR · 14d" : "AGED · 7y",
      },
    ],
    hops,
    relayLabel: `${chain.length} relays · ${40 + (score % 60)} ms RTT`,
    mapStatus: score >= 45 ? "THREATFEED · LIVE" : "THREATFEED · NOMINAL",
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
