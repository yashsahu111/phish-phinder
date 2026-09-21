# Dynamic Relay Node Grid Map

## Changes
- Replace the simple three-card route with the visual `NODE VIEW / THERMAL OVERLAY` grid map.
- Plot the three parsed relay IPs as status-colored nodes connected by dashed trajectory arcs.
- Show live threat-feed status and location labels from relay geolocation results.
- Make each node selectable and show a compact overlay with that relay's IP, MTA stage, verification status, source evidence, and available location/provider details.
- Preserve the current MailShield visual system and mobile layout.

## Technical details
- Reuse the existing parsed `a.hops` data so presets and submitted headers immediately redraw nodes, colors, and paths.
- Resolve geolocation for each unique relay IP server-side through the existing lookup function, while tolerating unavailable/private relay locations.
- Compute SVG node positions and curved paths from the current hop count rather than hardcoding sample IPs.

## Verification
- Exercise all four presets and confirm node IPs/statuses redraw.
- Select every node and verify its matching relay details appear.
- Check desktop/mobile rendering, browser errors, and build health.
