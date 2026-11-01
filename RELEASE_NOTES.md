# keenetic-firewall 4.0.13

- Display Security & Health database file sizes using explicitly labelled binary units (KiB, MiB, GiB), with base 1024 and localized decimal/group separators. For example, 46,231,552 bytes is displayed as 44.1 MiB and 286,720 bytes as 280 KiB (localized to 44,1 MiB / 280 KiB).
- Expose each exact byte count in a native size-cell tooltip and an accessible label, without rounding the underlying snapshot. Keep filenames and sizes rendered as text. Missing, invalid or unsafe byte counts remain Unavailable; zero-length files remain 0 B.
- Refresh Security UI cache references in both Security & Health and the Firewall page. Extend UI regression coverage with the reported database sizes, boundaries, zero/unknown/invalid values, exact localized tooltips and stale-tooltip prevention.

Package 2.0.24; Firewall component 4.0.13; Security UI and page 1.0.3; Firewall page 2.0.6. KeenTool manager remains 2.0.12. Disk capacity and security email storage formatting retain their existing decimal units. Database contents, maintenance policies, firewall rules, credentials and schedules are unchanged.

Install through coordinated KeenTool package 2.0.24, then reload Security & Health. Shared UI sources are included for review; installation remains coordinated by KeenTool.
