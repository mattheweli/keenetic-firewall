# Security & Health email preferences

Web Settings → Security & Health → Daily summary email controls only the daily summary. Turn it off while leaving Email enabled and Immediate alerts enabled to keep health/blocklist warnings. The defaults preserve existing email behavior. The summary hour is used only when summaries are enabled.

KeenTool → H Security / system health → D Daily summary email on/off provides the same setting. CLI alternative:

```sh
printf '%s' '{"digest_enabled":false}' | /opt/bin/bash /opt/bin/firewall_security settings
```

The next monitor cycle stops creating digests and removes queued digest messages before email delivery. Other queued warnings are retained. An email already being delivered cannot be recalled. Re-enabling summaries considers only the current day at the configured local hour, not a backlog of disabled days. The master email switch controls all Security & Health email; Pingtool and other tools retain their own notification settings.
