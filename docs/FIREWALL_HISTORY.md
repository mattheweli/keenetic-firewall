# Firewall IP history aggregation — 2.0.16 / 4.0.5

The default policy keeps original IP samples for at least 7 elapsed days, hourly buckets through 30 days, and local-calendar-day buckets thereafter. The key is time bucket + IP/subnet + list type. Counts are summed as SQLite integers. No IPs or list classifications are discarded. `drops` global history, `ip_info` enrichment/full port history, AbuseIPDB/reporting state and kernel counters are not changed.

## Configuration and operation

- KeenTool → Firewall → **History aggregation settings**.
- Web Settings → **Firewall history**, after administrator login.
- Persistent file: `/opt/etc/keentool/firewall-history.conf`.
- `HISTORY_ENABLED="true"`, `HISTORY_RAW_DAYS="7"`, `HISTORY_HOURLY_DAYS="30"`.
- Valid range: `1 <= HISTORY_RAW_DAYS <= HISTORY_HOURLY_DAYS <= 3650`.

The installer adds missing defaults and two runtime helpers, preserving existing configuration and databases. It does not aggregate during installation. The next normal firewall statistics job runs maintenance if due, before exporting the dashboard. Subsequent aggregation runs at most once per 24 hours, under the same writer lock as collection. No additional cron job is installed. Saving history settings does not apply firewall rules or restart services. Config changes take effect at the next due run; explicit maintenance can apply them immediately:

```sh
/opt/bin/bash /opt/bin/firewall_history status
/opt/bin/bash /opt/bin/firewall_history run
/opt/bin/bash /opt/bin/firewall_stats.sh force
```

`run` performs database maintenance only: it does not read/clear kernel counters or consume captures. `force` subsequently regenerates the dashboard and performs the normal collection cycle. The history status JSON includes the verified baseline backup location. A failed/deferred aggregation logs the reason and leaves statistics collection/export available. If database compaction is deferred by a reader, committed aggregates remain valid and later maintenance can reclaim the space.

## Precision and compatibility

Only historical time precision is reduced. All-time IP/list hit totals and calendar-day IP/list totals remain exact. Recent samples remain byte-for-byte equivalent in their original four fields. Time-window boundaries inside an hourly/daily bucket are approximate: the whole bucket is assigned to its start, never distributed into invented individual events. A window starting inside a bucket can omit that bucket's later events; a comparison splitting one can attribute all its hits to one side. Historical first/last timestamps become bucket starts. Firewall and Security pages disclose this limitation. Global Traffic History uses the untouched `drops` table.

Cutoffs are aligned to local midnight after subtracting the requested elapsed days, keeping complete boundary buckets and at least the specified recent duration. Repeated local hours remain distinct epoch buckets; 23- and 25-hour days are tested. The router timezone is recorded at the first aggregation. An unexpected timezone change stops later aggregation rather than silently moving existing daily totals to different dates.

Disabling aggregation stops further rollups. Increasing thresholds does not reconstruct detail already aggregated. Existing coarse buckets remain coarse. No history is deleted by age. The collector keeps its four explicit insert columns; the added `resolution` column defaults to 0 for new samples (3600 = hourly, 86400 = calendar day). Existing read queries remain compatible. Custom/normalized schemas or custom triggers are refused for manual review.

## Backup, checks and rollback

Before the first aggregation, SQLite creates an online baseline backup under `/opt/var/backups/keentool-db/history-*/firewall_stats.db`. The directory is private (0700), the file is 0600, and its full integrity check must pass. Space checks reserve room for the initial backup and SQLite work/compaction; temporary tables use file storage with a bounded cache. The backup is retained, not repeatedly duplicated by cron and not automatically deleted. It occupies disk space separately from the active database.

Each rollup is a single `BEGIN IMMEDIATE` transaction. SQL guards compare every IP/list total, every local calendar-day IP/list total and all untouched recent samples before commit. Integer overflow or validation failure rolls back the transaction, including the schema addition. An integrity check follows compaction. The backup is a baseline, not a continuously updated mirror: restoring it later would discard events collected since it was taken. Code/package rollback does not silently restore this database or recover time precision. For a data restore, stop collection/writers and use a separately reviewed SQLite restore procedure with a fresh backup of the current state.

## Measurements

A private supplied database was tested on copies, leaving the original unchanged. At its latest sample timestamp, the 7/30-day policy reduced 46,895,104 bytes to 43,778,048 bytes (6.6%). All 30,626,489 hits remained, with unchanged per-IP/list and calendar-day totals, global counters, metadata/port history and reporting tables. The modest immediate reduction reflects already summarized older data and many one-off IPs. Pure VACUUM alone previously reduced it to 44,130,304 bytes.

A separate simulation aged those same records by 31 days, without new incoming events: 30,748,672 bytes. This illustrates daily aggregation, not a prediction of a live database's future size. New addresses/events and port history still grow. These measurements are not physical-router execution or throughput claims. The user's database or its contents are never part of the public package/tests.

## Compact storage and balanced profile

See [DATABASE_STORAGE.md](DATABASE_STORAGE.md) for explicit IP dictionary conversion, the 2/7/365 balanced profile, optional monthly history and lossless Ping/vnStat compaction. Existing history configuration is preserved during installation. `keentool_db firewall balanced` explicitly selects the new policy; reduced older time precision is permanent.

New fresh installations use Balanced 2/7/365 and request compact storage as of 2.0.18. Existing saved policies are preserved on upgrade. Use KeenTool Firewall → 6 → 2 to explicitly adopt Balanced; see DATABASE_STORAGE.md.
