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
