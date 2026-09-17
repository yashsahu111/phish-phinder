# Threat Radar rebrand and dynamic threat context

## Changes
- Replace the visible Mail AI branding and page metadata with Threat Radar, including report/export references and footer copy.
- Extend the analysis result with a single dynamic Primary Threat Type and a plain-English Threat Context explanation.
- Classify results in this order so combined attacks remain understandable:
  1. Clean / Low Risk for scores below 20%.
  2. Identity Spoofing & Domain Impersonation for DMARC failure or SPF/DKIM misalignment.
  3. Malicious Payload / Link Hazard for dangerous attachments or suspicious links.
  4. Social Engineering & Phishing for urgent or financial solicitation language.
- Show the classification inside the Threat Score card and place a severity-colored explanation banner directly below it.

## Technical details
- Reuse the parser’s existing authentication, alignment, payload, link, and social-engineering findings rather than duplicating checks in the page.
- Add typed `threatType` and `threatContext` fields to the analysis output.
- Keep the existing visual system and responsive layout; add only compact metadata and banner styles.
- Verify safe, phishing, and unaligned-domain samples, then check the desktop and narrow layouts.
