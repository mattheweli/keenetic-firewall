# keenetic-firewall 4.0.1

Relative to published v4.0.0 (`55dc2b0404de3ddd0fa87e333ee7a91aeedfd0ca` on main).

- Aggregate older per-IP/list samples into hourly and daily buckets without deleting hit totals or IP/list identities. Leave recent raw samples unchanged. The `resolution` default preserves collector insert compatibility and existing read queries.
- Verify a private SQLite online backup before the first aggregation. Use a single guarded write transaction checking per-IP/list totals, local-day totals and recent samples, plus integrity checks, free-space preflight and the collector's writer lock. Refuse unexpected schema/triggers, invalid counts and timezone changes; preserve data on failure.
- Run maintenance at most daily from the existing statistics schedule, before dashboard export. Keep preview read-only and standalone maintenance independent of kernel/capture reads. Reclaim free pages with VACUUM; retain the original baseline backup separately.
- Respect local calendar days and repeated DST hours; retain existing coarser buckets when thresholds increase. Explain irreversible precision reduction and approximate period boundaries on the dashboard and in Security diagnostics.
- Add isolated real SQLite/PHP-core tests for aggregation, DST, exact totals/recent sample preservation, full port/report/global state, private backups, idempotence, disabled/increased policies, backup failure, integer-overflow rollback and writer locking. Existing installation, updater, security and UI checks remain in the suite.

See [FIREWALL_HISTORY.md](docs/FIREWALL_HISTORY.md) for policy, measured size reduction, configuration and baseline-backup limitations. Previous stable notes remain in [STABLE_2.0.0.md](docs/history/STABLE_2.0.0.md); alpha history is archived separately.

## Upgrade and history precision

Install the complete KeenTool 2.0.1 suite through `keentool --update`. Component sources require the coordinated runtime; do not install isolated scripts. Existing settings, credentials, schedules and databases are preserved by the installer. Missing history defaults are enabled (7 days of samples, hourly through 30 days, daily thereafter). Aggregation starts at the next normal firewall statistics job, after a verified private baseline backup, and then runs at most daily. Configure it in KeenTool → Firewall → History aggregation settings, or authenticated Settings → Firewall history.

All IP/list and calendar-day hit totals remain exact; older time precision is reduced irreversibly. Period boundaries crossing a bucket and historical first/last timestamps are approximate and labeled. Global counters, full port histories and reporting state are untouched. Increasing thresholds or disabling aggregation cannot reconstruct prior detail. The baseline backup is retained separately and occupies storage; restoring it later would lose events collected since that backup. See suite/docs/FIREWALL_HISTORY.md.

## Validation

45 isolated regression checks passed, including real SQLite/PHP-core aggregation, DST transitions, backup verification, rollback on integer overflow, writer locking and installer/updater compatibility. A private database copy reduced from 46.9 MB to 43.8 MB with all 30,626,489 hits and all metadata/global/report state preserved; production dashboard SQL/geography export passed. No private database is distributed. Physical-router execution/reboot and live SMTP were not independently tested for this patch.
