# MailShield Cyber Command Center upgrade

## Changes
- Fix Primary Threat Type by deriving four explicit categories from parsed evidence: `Clean / Authenticated Mail`, `Business Email Compromise (BEC)`, `Malicious Payload / Executable Risk`, and `Identity Spoofing & Domain Impersonation`.
- Rank concrete executable evidence above BEC language and identity-only failures, while keeping authenticated low-risk mail clean. Update the context, AI insight, and risk cards from the same winning classification so every section stays synchronized.
- Add four one-click presets at the top of the intake area for spoofing, clean mail, BEC, and executable payload scenarios.
- Replace the current map-style trace with a responsive, interactive hop-chain diagram showing origin, relays, and destination. Each node will expose its source header and show a verified or forged status.
- Turn SPF, DKIM, DMARC, and IP Geolocation badges into accessible controls. Selecting one opens a right-side forensic drawer with the matched raw line, result, reason, and relevant RFC reference.
- Add a collapsible live forensics terminal at the bottom. Its entries will be generated from the actual parse path, authentication checks, alignment results, artifact scan, geolocation state, and evidence-hash state.
- Change forensic export to open a legal evidence preview first. The preview will show a police-style seal treatment, case metadata, SHA-256 verification state, threat findings, and editable investigator name/designation fields; download remains the final action.

## Technical details
- Extend the analysis result with typed authentication evidence, hop source lines/statuses, inspector records, and parsing-log entries. Keep parsing deterministic and local; IP location remains the existing server-side lookup.
- Generate a real SHA-256 digest from the submitted artifact in the browser and use the same digest in the preview, terminal, and PDF rather than the current placeholder hash.
- Preserve the existing MailShield palette and visual identity while tightening layout density, focus states, keyboard access, drawer/modal behavior, and mobile stacking.
- Reuse the existing PDF tables, adding preview sign-off values and the computed hash to the final Form 65B document.

## Verification
- Exercise all four presets and confirm each produces the intended threat type, context, hop statuses, inspector evidence, and terminal output.
- Verify drawer, terminal, preview, sign-off fields, and PDF download with keyboard and pointer interactions.
- Check desktop and narrow mobile layouts, then confirm the preview build has no runtime or console errors.
