# Security & Health email preferences

Web Settings → Security & Health → Daily summary email controls only the daily summary. Turn it off while leaving Email enabled and Immediate alerts enabled to keep health/blocklist warnings. The defaults preserve existing email behavior. The summary hour is used only when summaries are enabled.

KeenTool → H Security / system health → D Daily summary email on/off provides the same setting. CLI alternative:

```sh
printf '%s' '{"digest_enabled":false}' | /opt/bin/bash /opt/bin/firewall_security settings
```

The next monitor cycle stops creating digests and removes queued digest messages before email delivery. Other queued warnings are retained. An email already being delivered cannot be recalled. Re-enabling summaries considers only the current day at the configured local hour, not a backlog of disabled days. The master email switch controls all Security & Health email; Pingtool and other tools retain their own notification settings.

## CLI state overview (2.0.20)

Open KeenTool H Security Monitoring. Notifications lists master email (7), immediate warnings (W), daily summaries (D), summary time (6) and timezone (T). ON / PAUSED means the preference is enabled but the master switch, transport configuration or monitor readiness prevents normal delivery. It is not proof of SMTP delivery. The main H entry shows the monitor and effective warning/daily states.

Menu groups separate Monitoring, Notifications, Access/protection and Blocklist/logging. Normal redraw only reads configuration, validated PID/socket state and cached observations; it does not run live firewall checks or scan databases/backups. The snapshot is labelled and stale/missing/future state is not treated as healthy. Option 1 performs live health checks, option 2 shows recent events and option 3 reviews configured bypasses. Legacy status/request JSON modes are preserved for automation.
