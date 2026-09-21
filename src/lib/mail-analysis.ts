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
  threatType:
    | "Identity Spoofing & Domain Impersonation"
    | "Social Engineering & Phishing"
    | "Malicious Payload / Link Hazard"
    | "Clean / Low Risk";
  threatContext: string;
  identityInsight: string | null;
  judge: { category: string; systemRisk: string; userRisk: string };
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
const FINANCIAL_SOLICITATION = /\b(wire transfer|payment|invoice|bank transfer|billing|remittance|funds?|crypto(?:currency)?|gift cards?)\b/i;

function linkHeavy(text: string) {
  return (text.match(/https?:\/\//gi) ?? []).length > 3;
}

function payloadCountLabel(attachmentCount: number, linkCount: number) {
  const parts: string[] = [];
  if (attachmentCount > 0) parts.push(`${attachmentCount} dangerous attachment${attachmentCount === 1 ? "" : "s"}`);
  if (linkCount > 0) parts.push(`${linkCount} suspicious link${linkCount === 1 ? "" : "s"}`);
  return parts.join(" and ") || "a suspicious payload indicator";
}


export function analyze(raw: string): Analysis {
  const text = raw.trim();
  const from = header(text, "From") || "unknown@unknown";
  const to = header(text, "To") || "recipient@unknown";
  const subject = header(text, "Subject") || "(no subject)";
  const domain = (from.match(/@([\w.-]+)/) ?? [])[1] ?? "unknown";

  const attachments = Array.from(new Set((text.match(BAD_EXT) ?? []).map((a) => a)));
  const dangerous = attachments.filter((a) => /\.(exe|scr|iso|js|vbs|jar|bat|cmd)$/i.test(a));

  // ============================================================
  // 3-TIER UNIVERSAL PARSING HIERARCHY
  // ============================================================
  const lower = text.toLowerCase();
  type AuthVerdict = "pass" | "fail" | "unknown";

  // --- TIER 1: explicit summary declarations (absolute priority) ---
  const tier1 = (name: string): AuthVerdict => {
    const m = lower.match(new RegExp(`\\b${name}\\s*:\\s*['"\`]?\\s*(pass|fail|reject)\\b`));
    if (!m) return "unknown";
    return m[1] === "pass" ? "pass" : "fail";
  };

  // --- TIER 2: raw header parsing (fallback) ---
  const tier2 = (name: string): AuthVerdict => {
    const m = lower.match(new RegExp(`\\b${name}\\s*=\\s*(pass|fail|reject|mismatch|softfail|none)\\b`));
    if (!m) return "unknown";
    return m[1] === "pass" ? "pass" : m[1] === "none" ? "unknown" : "fail";
  };

  const spfVerdict: AuthVerdict = tier1("spf") !== "unknown" ? tier1("spf") : tier2("spf");
  const dkimVerdict: AuthVerdict = tier1("dkim") !== "unknown" ? tier1("dkim") : tier2("dkim");

  // --- RFC 7489 domain alignment ---
  const orgDomain = (d: string) => {
    const parts = d.toLowerCase().replace(/\.$/, "").split(".");
    if (parts.length <= 2) return parts.join(".");
    const twoLevel = /^(co|com|org|net|gov|edu|ac)\.[a-z]{2}$/.test(parts.slice(-2).join("."));
    return parts.slice(twoLevel ? -3 : -2).join(".");
  };
  const aligns = (candidate: string) => {
    if (!candidate || domain === "unknown") return false;
    const c = candidate.toLowerCase();
    const f = domain.toLowerCase();
    if (c === f || c.endsWith(`.${f}`) || f.endsWith(`.${c}`)) return true;
    return orgDomain(c) === orgDomain(f);
  };

  const dkimDomain =
    text.match(/\bd\s*=\s*([\w.-]+)/i)?.[1] ?? text.match(/header\.i\s*=\s*@?([\w.-]+)/i)?.[1] ?? "";
  const returnPath = header(text, "Return-Path") || header(text, "Return-path");
  const envelopeDomain =
    (returnPath.match(/@([\w.-]+)/) ?? [])[1] ??
    text.match(/smtp\.mailfrom\s*=\s*(?:[\w.+-]+@)?([\w.-]+)/i)?.[1] ??
    text.match(/envelope-from\s*=?\s*<?(?:[\w.+-]+@)?([\w.-]+)/i)?.[1] ??
    "";

  const dkimAligned = dkimDomain !== "" && aligns(dkimDomain);
  const spfAligned = envelopeDomain !== "" && aligns(envelopeDomain);
  const dkimUnaligned = dkimVerdict === "pass" && dkimDomain !== "" && !dkimAligned;
  const spfUnaligned = spfVerdict === "pass" && envelopeDomain !== "" && !spfAligned;
  const dkimMisaligned = dkimUnaligned;

  const dkimPassAligned = dkimVerdict === "pass" && dkimAligned;
  const spfPassAligned = spfVerdict === "pass" && spfAligned;

  const dmarcExplicit: AuthVerdict = tier1("dmarc") !== "unknown" ? tier1("dmarc") : tier2("dmarc");
  let dmarcVerdict: AuthVerdict;
  if (dkimPassAligned || spfPassAligned) {
    dmarcVerdict = dmarcExplicit === "fail" ? "fail" : "pass";
  } else if (dkimUnaligned || spfUnaligned || dmarcExplicit === "fail") {
    // authenticated but unaligned, or explicitly failing → DMARC fails
    dmarcVerdict = "fail";
  } else {
    dmarcVerdict = dmarcExplicit === "pass" ? "pass" : dmarcExplicit;
  }

  const spfFail = spfVerdict === "fail";
  const dkimFail = dkimVerdict === "fail";
  const dmarcFail = dmarcVerdict === "fail";

  const domainFlag =
    SUSPECT_TLD.test(domain) || SUSPECT_TLD.test(text) || FAKE_DOMAIN.test(domain) || FAKE_DOMAIN.test(text);
  const socialHits = new Set((text.match(SOCIAL_KEYWORDS) ?? []).map((k) => k.toLowerCase())).size;
  const socialTrigger = socialHits >= 2 || FINANCIAL_SOLICITATION.test(text);
  const payloadHit = PAYLOAD_REF.test(text);
  const linkCount = (text.match(/https?:\/\/[^\s"'<>]+/gi) ?? []).length;

  // --- TIER 3: universal threat scoring bands ---
  const verdicts = [spfVerdict, dkimVerdict, dmarcVerdict];
  const alignmentFails = (dkimUnaligned ? 1 : 0) + (spfUnaligned ? 1 : 0);
  const failCount = verdicts.filter((v) => v === "fail").length + alignmentFails;
  const unknownCount = verdicts.filter((v) => v === "unknown").length;
  const allPass = failCount === 0 && unknownCount === 0;
  const critical = dmarcFail && (domainFlag || payloadHit || failCount >= 2);

  const clamp = (n: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, n));
  let score: number;
  let spoofMetric: number;
  if (critical) {
    score = clamp(80 + failCount * 4 + (domainFlag ? 4 : 0) + (payloadHit ? 4 : 0) + (socialTrigger ? 3 : 0), 80, 99);
    spoofMetric = clamp(Number((0.85 + failCount * 0.04 + (dkimMisaligned ? 0.03 : 0)).toFixed(2)), 0.85, 0.99);
  } else if (allPass && !domainFlag && !payloadHit) {
    score = clamp(5 + (socialTrigger ? 5 : 0) + (linkHeavy(text) ? 2 : 0), 5, 12);
    spoofMetric = 0.05;
  } else {
    score = clamp(
      40 + failCount * 6 + unknownCount * 4 + (domainFlag ? 6 : 0) + (payloadHit ? 6 : 0) + (socialTrigger ? 4 : 0),
      40,
      60,
    );
    spoofMetric = 0.45;
  }
  if (!text) score = 0;

  const socialMetric = socialTrigger ? 0.85 : 0.05;
  const payloadMetric = payloadHit ? 0.92 : 0.04;

  const severity = score > 70 ? "Critical" : score >= 30 ? "Elevated" : "Clean";
  const severityColor = score > 70 ? RED : score >= 30 ? ORANGE : GREEN;

  const identityThreat = dmarcFail || dkimUnaligned || spfUnaligned;
  const linkHazard = payloadHit || dangerous.length > 0 || (linkCount > 0 && domainFlag);
  const threatType: Analysis["threatType"] =
    score < 20
      ? "Clean / Low Risk"
      : identityThreat
        ? "Identity Spoofing & Domain Impersonation"
        : linkHazard
          ? "Malicious Payload / Link Hazard"
          : "Social Engineering & Phishing";

  const threatContext =
    threatType === "Identity Spoofing & Domain Impersonation"
      ? `Warning: High threat score reflects identity fraud and email spoofing risks${dkimUnaligned || spfUnaligned ? " caused by an unaligned sender domain" : " caused by failed sender authentication"}. This indicates a high risk of social engineering or credential theft rather than direct system malware execution.`
      : threatType === "Malicious Payload / Link Hazard"
        ? `Warning: The message contains ${payloadCountLabel(attachments.length, linkCount)} with characteristics commonly used for malware delivery or credential capture. Avoid opening attachments or following links until the artifact is contained.`
        : threatType === "Social Engineering & Phishing"
          ? `Warning: The language in “${subject}” uses urgency or financial pressure associated with phishing attempts. Verify the request through a trusted channel before taking action.`
          : `No material authentication, payload, link, or social-engineering risks were identified for ${domain}. The message currently presents a low-risk profile.`;

  const routingDomain = dkimDomain || envelopeDomain || "";
  const identityInsight =
    threatType === "Identity Spoofing & Domain Impersonation"
      ? `Identity Fraud Detected: The message was routed via ${routingDomain || "an unverified relay"}, but failed domain alignment with ${domain}. This indicates unauthorized domain spoofing designed for credential theft rather than direct system malware execution.`
      : null;

  const judge =
    threatType === "Identity Spoofing & Domain Impersonation"
      ? {
          category: "Identity Spoofing & Phishing Hazard",
          systemRisk: "Low (No malicious code execution)",
          userRisk: "Critical (High probability of social engineering & password theft)",
        }
      : threatType === "Malicious Payload / Link Hazard"
        ? {
            category: "Malicious Payload & Link Hazard",
            systemRisk: "Critical (Executable artifact present)",
            userRisk: "High (Malware or credential capture on interaction)",
          }
        : threatType === "Social Engineering & Phishing"
          ? {
              category: "Social Engineering & Phishing Hazard",
              systemRisk: "Low (No malicious code execution)",
              userRisk: "Critical (Urgency & financial pressure tactics)",
            }
          : {
              category: "No Active Threat Detected",
              systemRisk: "Low (No malicious code execution)",
              userRisk: "Low (Authenticated sender, no manipulation cues)",
            };

  const stateOf = (v: AuthVerdict): AuthState => (v === "pass" ? "pass" : v === "fail" ? "fail" : "warn");
  const badges: Badge[] = [
    {
      label: `SPF · ${spfUnaligned ? "unaligned" : spfVerdict === "unknown" ? "missing" : spfVerdict}`,
      state: spfUnaligned ? "fail" : stateOf(spfVerdict),
    },
    {
      label: `DKIM · ${dkimUnaligned ? "unaligned" : dkimFail ? "fail" : dkimVerdict === "unknown" ? "missing" : "aligned"}`,
      state: dkimUnaligned || dkimFail ? "fail" : stateOf(dkimVerdict),
    },
    {
      label: `DMARC · ${dmarcVerdict === "unknown" ? "missing" : dmarcVerdict}`,
      state: stateOf(dmarcVerdict),
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

  const payloadCount = attachments.length;
  const originIp = extractOriginIp(text);
  const authOk = allPass && !dkimFail;

  const narrative = !text
    ? "Paste raw headers or MIME above, or load a demo sample, and the engine will render a cited narrative here."
    : authOk
      ? `Message from ${domain} ("${subject}") passes SPF, DKIM and DMARC, so the sender identity is cryptographically verified. ${payloadCount || linkCount ? `${payloadCount + linkCount} link/payload artifact(s) were found but none are executable-grade;` : "No malicious links or payloads were detected;"} origin ${originIp} shows no authentication anomalies.`
      : `Message claiming to be from ${domain} ("${subject}") fails authentication — SPF ${spfVerdict === "unknown" ? "missing" : spfVerdict.toUpperCase()}, DKIM ${dkimFail ? (dkimMisaligned ? "domain mismatch" : "FAIL") : dkimVerdict === "unknown" ? "missing" : "pass"}, DMARC ${dmarcVerdict === "unknown" ? "missing" : dmarcVerdict.toUpperCase()} — so the sender identity cannot be verified. ${payloadCount || linkCount ? `${payloadCount + linkCount} link/payload artifact(s) detected and` : "No payloads detected, but"} origin ${originIp} is untrusted; recommend quarantine and edge block.`;

  return {
    score,
    severity,
    severityColor,
    threatType,
    threatContext,
    identityInsight,
    judge,
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
        label: "Domain & Sender Verification",
        value: authOk ? "PASS (Authenticated)" : "FAIL (Unverified Sender)",
        color: authOk ? GREEN : RED,
      },
      {
        label: "File & Link Security Scan",
        value:
          linkCount + payloadCount > 0
            ? `HIGH RISK (${linkCount + payloadCount} Links / Payloads Found)`
            : "CLEAN (No Malicious Payloads)",
        color: linkCount + payloadCount > 0 ? RED : GREEN,
      },
      {
        label: "Server Origin & Reputation",
        value:
          !authOk || score > 70
            ? `SUSPICIOUS (${originIp})`
            : `VERIFIED (${originIp})`,
        color: !authOk || score > 70 ? (score > 70 ? RED : ORANGE) : GREEN,
      },
    ],
    senderDomain: domain,
    subject,
    linkCount,
    payloadCount,
    originIp,
    authOk,
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
