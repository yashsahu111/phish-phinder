/**
 * Accepted release identity for MailShield.
 *
 * This is the single source of truth for "which version is approved".
 * The health endpoint reports these values from whatever bundle is actually
 * running, so fetching the endpoint on a live host tells you whether that
 * host is serving this exact accepted version.
 *
 * Bump RELEASE_VERSION (and RELEASE_NOTE) whenever a new version is accepted.
 */
export const RELEASE = {
  app: "MailShield",
  version: "4.2.0",
  channel: "stable",
  /** Short marker for the accepted (reverted) baseline commit. */
  baseline: "20647bf",
  releasedAt: "2026-09-21",
  note: "Reverted stable build accepted as final website.",
} as const;

export type Release = typeof RELEASE;

/** Stable fingerprint of the accepted release identity. */
export function releaseFingerprint(): string {
  const basis = `${RELEASE.app}|${RELEASE.version}|${RELEASE.channel}|${RELEASE.baseline}|${RELEASE.releasedAt}`;
  // FNV-1a 32-bit — deterministic, dependency-free, identical on server and client.
  let h = 0x811c9dc5;
  for (let i = 0; i < basis.length; i++) {
    h ^= basis.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}
