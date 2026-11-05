# Keenetic Firewall 4.0.14

## Coordinated package 2.0.25 / Firewall 4.0.14 — 2026-11-05

- Expose the Firewall IP/subnet input and Check button to read-only visitors. Support IPv4, IPv6 and CIDR queries, including Enter to submit, using the existing read-only diagnostics API.
- Keep Ban, Unban, duration and note fields hidden and disabled until administrator login. Preserve the public query across authentication refresh and logout; clear the private note.
- Clarify Unban confirmation and results: remove manual/dynamic ban entries without adding a whitelist entry, and report any remaining list memberships. Static blocklists and GeoIP can still block the address; future detections can ban it again.
- Add browser-logic and CGI regressions for public diagnostics, private controls and administrator/CSRF enforcement.

Package 2.0.25; Firewall component 4.0.14; Firewall page 2.0.7. KeenTool manager remains 2.0.12. No firewall rule, database, password or schedule migration is required.

Install through KeenTool u and reload the Firewall page.
