# keenetic-firewall 4.0.10

- Display Top Threats & Targets in three columns at desktop viewport widths of 1,200px and above, two columns from 800px, and one column on smaller screens. Apply the same layout to all four periods and both rows of tables.
- Give each table an equal scroll viewport, up to 600px and capped at 65% of viewport height. Keep column headings sticky while independently scrolling each table.
- Wrap full IPv6 addresses, source/subnet details, port badges and organization names instead of forcing wide tables or truncating metadata. Keep CNT/HITS numbers intact on one line and retain Details and +N port controls.
- Add a real Chromium layout check across eight viewport widths, two densities and four periods, including long IPv6 addresses, large counters, wrapping, internal scrolling and sticky headers.

Package 2.0.21; Firewall component 4.0.10; Firewall dashboard 2.0.3. KeenTool manager remains 2.0.12, Main Dashboard 2.0.4, Stats 4.0.2 and hook 3.0.1. Filtering policy, databases, credentials and schedules are unchanged.

Install using coordinated KeenTool package 2.0.21 (manager remains 2.0.12), then reload the Firewall page.

# keenetic-firewall 4.0.9

Reorganize Security Monitoring into Overview, Monitoring, Notifications, Access/protection and Blocklist/logging groups. Display current service, interval, master email, immediate warning/daily summary states, summary time/timezone, management/isolation/pending state and thresholds. Immediate warning email has a W control; existing shortcuts including D remain. ON / PAUSED distinguishes enabled preferences from missing transport/master email/monitor readiness.

KeenTool manager 2.0.12 shows the lightweight status on its main H entry. Normal redraw reads configuration, validated PID/socket state and cached observations without kernel commands, DB/network work or backup scans. Missing/stale/future snapshots are not shown healthy. Explicit health, event and bypass actions are focused readable views; legacy status/request JSON modes stay compatible. Do not print credentials or terminal control characters.

Requires coordinated package 2.0.20, Security engine 1.0.5, CLI 1.0.2 and new private security_menu.php 1.0.0. Stats stays 4.0.2; installer/guardian and filtering policy are unchanged. Regression fixtures cover effective states, readiness, stale/missing/future snapshots, no expensive redraw calls, read-only events, warning toggle/redraw, main-menu fallback and credential non-disclosure.

# keenetic-firewall 4.0.8

Add an independent Daily summary email switch in Web Settings and KeenTool Security menu D. Turning it off stops new digests and discards queued digests only, preserving immediate health/blocklist warnings under their master controls. Existing default behavior remains enabled; other tools' notifications are unchanged.

Recognized healthy managed guarded hooks update without repeat activation consent or an SSH challenge after the general coordinated-update approval. Validate source baselines, managed metadata and health, revalidate eligibility under the hook lock and keep independent owned-rule/source rollback and bounded family verification. Initial legacy/custom or unhealthy source retains first-migration review; disabled firewalls remain disabled. Failed automatic health checks restore the prior source/rules. No database policy changes are introduced.

Requires coordinated KeenTool package 2.0.19, installer 1.0.8, transaction engine 1.0.6 and guardian 1.0.2. Security/Settings engines are 1.0.4; Security CLI 1.0.1. Manager remains 2.0.11, Stats 4.0.2. See docs/SECURITY_EMAIL.md and docs/FIREWALL_UPGRADE.md. Real PHP/file and mocked-kernel regressions cover digest cancellation/warning delivery, no-terminal adopted-hook success, rollback on health failure, initial interactive migration and unknown/disabled refusal. Physical router reachability and mail delivery are not claimed by these fixtures.

# keenetic-firewall 4.0.7

Balanced optimization is now available in KeenTool → 3 Firewall Suite → 6 History aggregation settings → 2 Apply Balanced profile now. The action explains the verified backup, compact storage, 2/7/365-day policy and permanent reduction of older temporal precision, then requires confirmation. Status, custom precision and saved-policy maintenance remain available.

Coordinated package 2.0.18 defaults new fresh installs to Balanced and compact IP storage at first due statistics maintenance. The installer does not convert databases itself. Existing saved policies are preserved on upgrade; omitted legacy compact/monthly fields retain false/0 behavior. Web Settings exposes compact-storage control and Balanced presets. Explicit storage expansion disables automatic reconversion and preserves current events without reconstructing old precision.

History CLI/engine and database engine are 1.0.2; Settings engine 1.0.3. Manager remains 2.0.11, Stats 4.0.2 and filtering rules unchanged. Requires the coordinated installer/runtime. Exact-source suite regression checks cover consent/decline, defaults, legacy preservation, first due conversion, totals, cadence and expansion; physical-router speed/custom services are not claimed.

# keenetic-firewall 4.0.6

Explicit balanced maintenance now guarantees a fresh verified backup when the database is already compact. A conversion backup is reused only within the same invocation; an earlier history/normalization backup is not a current recovery copy. Regression fixtures verify first and repeated balanced runs and the current rows in the latest backup.

Includes the optional compact IP dictionary, balanced 2/7/365-day history and shared lossless Ping/vnStat maintenance from 4.0.5. Installation preserves databases/settings until maintenance is explicitly requested. Update through coordinated package 2.0.17 and review docs/DATABASE_STORAGE.md. Database engine 1.0.1; Stats remains 4.0.2, manager 2.0.11 and other tools unchanged. Old temporal precision cannot be restored by expansion or code rollback.

# keenetic-firewall 4.0.5 / Stats 4.0.2

Optional compact IP history storage replaces repeated IP strings with integer identifiers, with exact row/multiplicity validation and compatible reads/inserts. An explicit balanced 2/7/365-day profile keeps recent samples, then hourly/daily and old calendar-month IP/list totals. All hit totals remain; older temporal boundaries and first/last precision are approximate. Global counters, complete port strings, metadata and report state are unchanged. Unknown schemas/indexes/triggers are refused.

Update through coordinated KeenTool package 2.0.16, then review docs/DATABASE_STORAGE.md. Installing does not convert databases or change existing history settings. Root SSH commands keentool_db firewall compact and keentool_db firewall balanced provide structural-only or balanced optimization with private verified backups. Expansion retains current events for a reviewed storage downgrade; never restore an old database backup as an automatic code rollback. New shared helpers also support lossless Ping/vnStat compaction, with guarded vnStat daemon lifecycle. Manager stays 2.0.11; other tool versions do not change.

Isolated real SQLite/PHP-core tests cover row multiplicity, totals, monthly precision, recent samples, compatibility writes, private backup/failure, idempotence, expansion, custom-index refusal, lossless Ping/traffic data and vnStat service errors. Private user databases are not release/test assets. Physical-router performance and custom init scripts are not verified.

# keenetic-firewall 4.0.4

Fix guardian readiness polling on BusyBox builds which reject fractional sleep. Guardian 1.0.1 uses whole seconds; Hook 3.0.1, Monitor 4.0.0, Stats 4.0.1 and Manager 3.0.0 retain their versions.

The coordinated package 2.0.15 also fixes rollback service handling: leave untouched running vnStat alone, restore verified source despite service errors and report incomplete recovery. A separate SHA-256-verified recover-firewall-upgrade.sh asset restores an interrupted same-boot 2.0.14 transaction through its original pinned guardian. Keep the recovery directory and inspect phase/logs/services; do not retry 2.0.14 over a pending transaction. See the KeenTool 2.0.15 release and docs/FIREWALL_UPGRADE.md. No password reset, database pruning, list replacement or cron change is introduced.

## Installation and validation

Update through KeenTool coordinated package 2.0.15. Do not install isolated component files into an older suite. The suite checks force integer-only sleep and reproduce the exact previous guardian/rollback with an untouched-vnStat stop failure, then exercise the standalone recovery entry with real file operations and mocked service/kernel state. No physical-router recovery is claimed. The historical missing web permission ledger warning is separate and is not repaired by guessing permissions.

## Previous release notes

# keenetic-firewall 4.0.3

Hook 3.0.1 participates in the coordinated suite's guarded migration: explicit application consent, IPv4/IPv6 health verification and a fresh SSH challenge. An independent guardian restores previous owned rules, metadata and source if application fails or confirmation is missing. New router-triggered reapplications are blocked while pending; reboot recovery restores previous source before invoking the old hook.

Deferring retains the previous boot hook, including when permanent source backups are declined. Disabled firewalls stay disabled. Foreign router rules, existing bans, credentials, statistics and schedules are preserved. Monitor 4.0.0, Stats 4.0.1 and Manager 3.0.0 keep their versions. The private guard helper source is included for transparency and is installed by the coordinated package, not this component on its own.

## Installation

Install/update KeenTool coordinated package **2.0.14** through KeenTool → u, approve guarded application and type the fresh challenge while SSH remains usable. After upgrading the updater, a deferred migration can be retried with `keentool --update --reinstall --apply-firewall`. Do not copy isolated component files into an older suite: the guarded installer, marker handling and independent recovery copies must ship together. See docs/FIREWALL_UPGRADE.md.

## Validation

The coordinated suite's guardian tests exercise the real hook/helper and real file transactions against a mocked kernel, including confirmation/rejection, independent recovery after parent SIGKILL, failed family/restore paths, foreign-rule/bans retention and reboot recovery. The exact successful coordinated release commit and workflow are recorded in the KeenTool release. Physical-router connectivity/reboot is not inferred from isolated tests.

## Previous release notes

# keenetic-firewall 4.0.2

Refresh shared UI/security asset references for configured snapshot freshness. No hook, filtering, statistics collection or database policy change. Monitor remains 4.0.0, Stats 4.0.1; firewall HTML advances to 2.0.2. Update the explanatory README with a synthetic interface screenshot.

## Installation

Update through the complete verified KeenTool 2.0.5 suite. This component depends on its shared runtime/assets; do not copy isolated sources over an older installation. Existing settings, credentials, schedules and databases are preserved. See README.md and the suite installation guide. The screenshot shows actual templates with synthetic example data.

## Validation

The complete suite is checked on the exact KeenTool release commit, including configured freshness, refresh behavior, file transactions and component regression tests. These component algorithms are unchanged; this patch refreshes shared asset references and documentation. No physical-router reboot or live SMTP is claimed.


# keenetic-firewall changelog

## 4.0.1 — 2026-10-23

Relative to published v4.0.0 (`55dc2b0404de3ddd0fa87e333ee7a91aeedfd0ca` on main).

- Aggregate older per-IP/list samples into hourly and daily buckets without deleting hit totals or IP/list identities. Leave recent raw samples unchanged. The `resolution` default preserves collector insert compatibility and existing read queries.
- Verify a private SQLite online backup before the first aggregation. Use a single guarded write transaction checking per-IP/list totals, local-day totals and recent samples, plus integrity checks, free-space preflight and the collector's writer lock. Refuse unexpected schema/triggers, invalid counts and timezone changes; preserve data on failure.
- Run maintenance at most daily from the existing statistics schedule, before dashboard export. Keep preview read-only and standalone maintenance independent of kernel/capture reads. Reclaim free pages with VACUUM; retain the original baseline backup separately.
- Respect local calendar days and repeated DST hours; retain existing coarser buckets when thresholds increase. Explain irreversible precision reduction and approximate period boundaries on the dashboard and in Security diagnostics.
- Add isolated real SQLite/PHP-core tests for aggregation, DST, exact totals/recent sample preservation, full port/report/global state, private backups, idempotence, disabled/increased policies, backup failure, integer-overflow rollback and writer locking. Existing installation, updater, security and UI checks remain in the suite.

See [FIREWALL_HISTORY.md](docs/FIREWALL_HISTORY.md) for policy, measured size reduction, configuration and baseline-backup limitations. Previous stable notes remain in [STABLE_2.0.0.md](docs/history/STABLE_2.0.0.md); alpha history is archived separately.


Baseline: `85567431ac3b5ba7c7f4e3a965b63db1d9c684ad`.

- Firewall repository 4.0.0 coordinates monitor/statistics 4.0.0, hook/manager/updater/VPN/abuse tools 3.0.0 and dashboard/API/loader 2.0.0. New security helpers are 1.0.0.
- Hook: dual-family staged/preflight apply, owned-chain replacement and recovery, exact jump teardown, bounded NFLOG independent of DROP, explicit bypasses, coherent enable/IPv6 switches and timeout-capable managed manual bans. Avoid global tcpdump termination.
- Restore saved static/GeoIP/manual/dynamic sets before filtering, including partially populated sets; preserve saved timeout semantics and checkpoint only verified state. Persistent PCAP path and incremental cursor survive normal updates/reboot handling.
- Validate/cache each source, stage kernel sets before swap, reject empty/incomplete/main-list catastrophic shrink candidates, retain installed lists on failure. GeoIP size changes use advisory thresholds and explicit policy baselines. Record detailed download/staging/persistence/cache causes, current/previous counts and last successful installation.
- Password-only admin, HTTPS/CSRF/session/boot checks, guest read-only logs and hidden write controls, root command broker and optional reviewed web privilege separation. Manual ban TTL, IP/subnet diagnostics, event timeline, health summaries and typed Settings are supplied by the shared runtime.
- Preserve historical records and full port lists; portable AWK generation, grouped counters, expandable port badges, IPv6 difference/total display, readable ULOGD timestamps, geographic chart improvements and aligned responsive tables.
- Explicit lossless database optimization with verified SQLite backup and integrity checks; no implicit pruning/rollup. Shared HTML/plain periodic reports and detailed colored security digest.
- IPdeny IPv6 KP HTTP 404/cache age limitations remain documented. Source failures never imply automatic exclusion of a country.
