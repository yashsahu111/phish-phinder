#!/usr/bin/env node
/**
 * Deployment health check.
 *
 * Fetches /api/public/health from a live host and compares the release identity
 * it reports against the accepted release in src/lib/release.ts.
 *
 * Usage:
 *   node scripts/check-deployment.mjs https://your-app.vercel.app
 *   node scripts/check-deployment.mjs            # defaults to http://localhost:8080
 *
 * Exit code 0 = live build matches the accepted version.
 * Exit code 1 = mismatch, unreachable host, or bad response.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const releaseSrc = readFileSync(resolve(here, "../src/lib/release.ts"), "utf8");

const field = (name) => {
  const m = releaseSrc.match(new RegExp(`${name}:\\s*"([^"]*)"`));
  if (!m) throw new Error(`Could not read "${name}" from src/lib/release.ts`);
  return m[1];
};

const expected = {
  app: field("app"),
  version: field("version"),
  channel: field("channel"),
  baseline: field("baseline"),
  releasedAt: field("releasedAt"),
};

function fingerprint(r) {
  const basis = `${r.app}|${r.version}|${r.channel}|${r.baseline}|${r.releasedAt}`;
  let h = 0x811c9dc5;
  for (let i = 0; i < basis.length; i++) {
    h ^= basis.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

const base = (process.argv[2] ?? "http://localhost:8080").replace(/\/+$/, "");
const url = `${base}/api/public/health`;

console.log(`Checking ${url}`);

let res;
try {
  res = await fetch(url, { headers: { accept: "application/json" } });
} catch (err) {
  console.error(`FAIL  Host unreachable: ${err.message}`);
  process.exit(1);
}

if (!res.ok) {
  console.error(`FAIL  Health endpoint returned HTTP ${res.status}`);
  console.error(`      Body: ${(await res.text()).slice(0, 300)}`);
  process.exit(1);
}

let live;
try {
  live = await res.json();
} catch {
  console.error("FAIL  Health endpoint did not return JSON (host may be serving a stale or static build).");
  process.exit(1);
}

const expectedFp = fingerprint(expected);
const rows = [
  ["app", expected.app, live.app],
  ["version", expected.version, live.version],
  ["channel", expected.channel, live.channel],
  ["baseline", expected.baseline, live.baseline],
  ["releasedAt", expected.releasedAt, live.releasedAt],
  ["fingerprint", expectedFp, live.fingerprint],
];

let ok = true;
console.log("\n  field         accepted              live");
console.log("  ------------  --------------------  --------------------");
for (const [name, want, got] of rows) {
  const match = want === got;
  if (!match) ok = false;
  console.log(`  ${match ? "OK  " : "DIFF"} ${name.padEnd(12)} ${String(want).padEnd(20)}  ${String(got)}`);
}

console.log("");
if (ok) {
  console.log(`PASS  Live build at ${base} matches the accepted release (${expected.version} / ${expectedFp}).`);
  process.exit(0);
}

console.error(`FAIL  Live build at ${base} does NOT match the accepted release.`);
console.error("      The host is serving an older or different build. Redeploy the latest commit.");
process.exit(1);
