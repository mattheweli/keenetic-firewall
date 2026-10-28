# Compact storage and lossless database maintenance

Package 2.0.16 provides explicit maintenance commands. Installation only installs the helpers; it does not convert databases, change existing history settings or stop vnStat. Run commands as root from SSH with Entware Bash. Every modifying command creates a private integrity-verified SQLite online backup first, requires free working space and uses the same writer lock as the corresponding collector. Keep that database backup independently of the optional installation backup.

## Firewall: recommended balanced profile

```sh
/opt/bin/bash /opt/bin/firewall_history status
/opt/bin/bash /opt/bin/keentool_db firewall balanced
/opt/bin/bash /opt/bin/firewall_stats.sh force
```

`firewall_history optimize` is an alias for the balanced action. It converts repeated IP/subnet strings in IP hit history to integer references, retaining every row and duplicate multiplicity during conversion. A compatibility view continues to expose timestamp/IP/count/list/resolution and accepts the collector's existing inserts. Only recognized source schemas/indexes are accepted. Global `drops`, IP metadata, complete ordered port strings, report state and kernel counters are unchanged. Port normalization was not assumed to save space: a per-port relation can be larger for sparse sets, so this release retains the exact strings.

Balanced configuration keeps at least two elapsed days of original samples, hourly buckets through seven days, local-calendar-day buckets through 365 days and calendar-month buckets thereafter. Complete boundary days/months are kept rather than shortening these minimum durations. Existing coarse records cannot regain lost detail. Monthly resolution is tagged 2592000 as a level identifier, not a fixed-length month: actual calendar boundaries are used. Repeated hours and 23/25-hour local days remain supported.

All-time IP/list totals and calendar-month IP/list totals remain exact. Calendar-day totals remain exact outside old monthly buckets. Recent raw samples remain unchanged. First/last seen and rolling period comparisons inside any coarse bucket are approximate; monthly buckets increase that limitation for old periods. Global chart/top-day history uses unchanged `drops` data. Reducing time precision is permanent unless a pre-aggregation backup is restored, which would discard subsequent collected events. The balanced action is explicit; normal upgrades preserve existing settings. Settings exposes optional daily-through days: 0 disables further monthly aggregation. Increasing retention/turning monthly aggregation off never expands already coarse data.

Prefer structural compaction without changing time precision:

```sh
/opt/bin/bash /opt/bin/keentool_db firewall compact
```

`compact` is idempotent once converted. Subsequent due history maintenance still vacuums when performing rollups. To return to the text-backed schema while retaining all current events, run `keentool_db firewall expand` before downgrading to unsupported older runtimes. Expansion changes storage only; it cannot restore earlier time precision. Source rollback never silently restores a database backup. Custom triggers/indexes are refused for manual review.

## Connection Monitor

```sh
/opt/bin/bash /opt/bin/keentool_db ping status
/opt/bin/bash /opt/bin/keentool_db ping compact
```

Lossless VACUUM reclaims free space left by the configured retention deletes. It retains every existing IPv4/IPv6 sample, latency/loss peak and timestamp; no averaging or new retention policy is applied. Collection cannot run concurrently under the shared `pingtool` writer lock. Read-only clients can delay compaction; a failure retains the verified backup. A small or already compact database may not shrink.

## Traffic Monitor / vnStat

```sh
/opt/bin/bash /opt/bin/keentool_db traffic status
/opt/bin/bash /opt/bin/keentool_db traffic compact
```

vnStat already maintains its own historical aggregation. Its schema, retention, traffic counters and interface selection are left unchanged. The helper reads DatabaseDir from the literal vnStat configuration (default /opt/var/lib/vnstat), using vnstat.db. A custom path can be supplied explicitly with KT_VNSTAT_DB. It refuses an unavailable/non-SQLite database. For compact only, a running vnstatd is stopped through exactly one executable init script, checked stopped, then restarted on success or error. An initially stopped daemon remains stopped. Ambiguous init scripts are refused. Collection is briefly paused; counters not persisted by vnStat outside its normal shutdown guarantee cannot be reconstructed by this tool. Restart failure is reported as failure, not a successful complete maintenance operation.

## Other state

SMB Backup has no historical statistics database of its own. Security, settings, WAN and Entware state use configuration/JSON files; this command does not prune them. The SMB backup tool continues to take online snapshots of SQLite files. No arbitrary database path is accepted from the web; these are root CLI maintenance actions.

## Validation

Regression checks cover real SQLite/PHP-core conversion, duplicate rows, compatibility inserts/deletes, exact IP/list/month totals, recent samples, unchanged ports/global/reporting state, monthly precision, expansion retaining current data, idempotence, custom-index refusal, private backup, ping/traffic lossless VACUUM and shared writer locks. Isolated daemon fixtures exercise vnStat running/stopped/error paths. They do not establish physical router speed or service behavior for custom init scripts.

## Private sample measurements

On a private 58,638,336-byte sample, a local SQL structural simulation used 45,768,704 bytes with the IP dictionary alone and 39,247,872 bytes after the balanced profile (approximately 33% smaller). All 31,145,632 hits remained. This sample contains less than one year of IP history, so monthly buckets do not yet contribute to that saving. These figures are dataset-specific SQL simulations, not a live-router execution of the PHP maintenance helper or a future size cap. Synthetic PHP-core regression fixtures separately validate the actual helper. The private database is not distributed or uploaded as a test fixture.
