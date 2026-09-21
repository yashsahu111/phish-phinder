# Interactive Origin Trace Enhancement

## Goal
Restore the “Origin trace · hop chain” as an animated, selectable relay graph and keep the adjacent IP Forensics panel synchronized with the currently selected node.

## Changes
- Rename and reframe the relay map as “Origin trace · hop chain.”
- Add the requested graph metadata: grid coordinates, node/thermal modes, and live threat-feed status.
- Preserve dynamic dashed trajectory arcs and strengthen their moving/pulsing treatment while respecting reduced-motion settings.
- Show each parsed relay as a glowing, role-colored node: origin/threat, transit relay, and destination.
- Place resolved city labels above nodes, with clear fallbacks when geolocation is unavailable.
- Add the “Select a node to inspect the relay” prompt and a persistent bottom status banner containing stage, IP, host/reverse-DNS status, and deterministic RTT latency.
- Make node selection update the adjacent IP Forensics card instead of opening an overlapping map popup.
- Populate the side panel from the selected node and its geolocation result: IP, city/country, ISP/organization, and coordinates.
- Reset selection to the parsed origin whenever a new email is analyzed; all IPs, arcs, labels, and details remain driven by the current email headers.

## Verification
- Test spoof, clean, BEC, and payload presets to confirm each graph refreshes from parsed headers.
- Click every visible relay and confirm the side panel and bottom status banner update together.
- Check desktop and mobile layouts, keyboard node selection, animation behavior, and preview errors.

## Technical Notes
- Reuse the existing server-side IP geolocation lookup and parsed `hops` model.
- Add dynamic display helpers only; no changes to threat scoring, authentication parsing, PDF export, or dispatch behavior.
