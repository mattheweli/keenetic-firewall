# keenetic-firewall 4.0.9

Reorganize Security Monitoring into Overview, Monitoring, Notifications, Access/protection and Blocklist/logging groups. Display current service, interval, master email, immediate warning/daily summary states, summary time/timezone, management/isolation/pending state and thresholds. Immediate warning email has a W control; existing shortcuts including D remain. ON / PAUSED distinguishes enabled preferences from missing transport/master email/monitor readiness.

KeenTool manager 2.0.12 shows the lightweight status on its main H entry. Normal redraw reads configuration, validated PID/socket state and cached observations without kernel commands, DB/network work or backup scans. Missing/stale/future snapshots are not shown healthy. Explicit health, event and bypass actions are focused readable views; legacy status/request JSON modes stay compatible. Do not print credentials or terminal control characters.

Requires coordinated package 2.0.20, Security engine 1.0.5, CLI 1.0.2 and new private security_menu.php 1.0.0. Stats stays 4.0.2; installer/guardian and filtering policy are unchanged. Regression fixtures cover effective states, readiness, stale/missing/future snapshots, no expensive redraw calls, read-only events, warning toggle/redraw, main-menu fallback and credential non-disclosure.
