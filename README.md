# keenetic-firewall 4.0.0

Stable component sources for the KeenTool suite. Release date: 2026-10-22.

## Installation and updates

Install the complete KeenTool 2.0.0 release from https://github.com/mattheweli/KeenTool/releases. The shared runtime, assets, authentication and security broker are required. Do not copy this component alone over an older installation.

For an extracted complete package, use /opt/bin/bash ./install.sh --plan and follow docs/INSTALL.md. Existing public-source and local-alpha installations use --mode upgrade. New installations require --interface and reviewed web/logging ownership options. Existing databases, configuration, credentials and upgrade schedules are preserved.

## Changes

- Firewall repository 4.0.0 coordinates monitor/statistics 4.0.0, hook/manager/updater/VPN/abuse tools 3.0.0 and dashboard/API/loader 2.0.0. New security helpers are 1.0.0.
- Hook: dual-family staged/preflight apply, owned-chain replacement and recovery, exact jump teardown, bounded NFLOG independent of DROP, explicit bypasses, coherent enable/IPv6 switches and timeout-capable managed manual bans. Avoid global tcpdump termination.
- Restore saved static/GeoIP/manual/dynamic sets before filtering, including partially populated sets; preserve saved timeout semantics and checkpoint only verified state. Persistent PCAP path and incremental cursor survive normal updates/reboot handling.
- Validate/cache each source, stage kernel sets before swap, reject empty/incomplete/main-list catastrophic shrink candidates, retain installed lists on failure. GeoIP size changes use advisory thresholds and explicit policy baselines. Record detailed download/staging/persistence/cache causes, current/previous counts and last successful installation.
- Password-only admin, HTTPS/CSRF/session/boot checks, guest read-only logs and hidden write controls, root command broker and optional reviewed web privilege separation. Manual ban TTL, IP/subnet diagnostics, event timeline, health summaries and typed Settings are supplied by the shared runtime.
- Preserve historical records and full port lists; portable AWK generation, grouped counters, expandable port badges, IPv6 difference/total display, readable ULOGD timestamps, geographic chart improvements and aligned responsive tables.
- Explicit lossless database optimization with verified SQLite backup and integrity checks; no implicit pruning/rollup. Shared HTML/plain periodic reports and detailed colored security digest.
- IPdeny IPv6 KP HTTP 404/cache age limitations remain documented. Source failures never imply automatic exclusion of a country.

## Release baseline

Public main commit: 85567431ac3b5ba7c7f4e3a965b63db1d9c684ad. No tags or GitHub Releases existed at preparation time. Stable tag: v4.0.0.

See the complete package's CHANGELOG.md, VERSIONS.md, SECURITY.md and docs/VALIDATION.md for coordinated versions, installation, known feed limitations and test evidence. Development history is archived in docs/history/.
