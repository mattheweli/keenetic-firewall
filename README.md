# Keenetic Firewall

**Dual-stack firewall filtering, blocklist maintenance and a web dashboard for Keenetic / Entware.** Uses kernel `ipset` sets and owned iptables chains; performance depends on the router, list sizes and traffic workload.

Current firewall component: **4.0.2**. Independent scripts remain Monitor **4.0.0**, Stats **4.0.1**, Manager **3.0.0** and netfilter hook **3.0.0**. The suite version is not inferred from the Monitor script.

![Firewall dashboard with IPv4/IPv6 lists and filtering status](https://raw.githubusercontent.com/mattheweli/KeenTool/main/docs/screenshots/firewall.png)

## Features

- IPv4/IPv6 Internet blocklists, GeoIP country lists, manual entries, temporary bans and VPN-related lists.
- Validated downloads, per-source caching, saved sets restored at boot, list update results and actionable source errors.
- Staged owned-chain updates, verification across enabled address families and guarded administrator changes with confirmation/rollback.
- Read-only IP/subnet diagnostics: set membership, rule references, historical counters, metadata and bypass context.
- Port expansion, country ranking/map, period comparisons and readable NFLOG/ulogd-derived records.
- Shared HTTPS administrator authentication, CSRF checks and optional web privilege separation through the root command broker.

## How filtering and statistics differ

Set membership does not prove that a packet was dropped. Filtering also depends on enable flags, linked rules, input interface, bypasses, established connections and rule order. Use `firewall_health` for rule verification and the dashboard's IP diagnostics for context.

Historical counts describe the recorded database/PCAP sampling pipeline, not necessarily every live packet. Country metadata identifies recorded sources, not attribution to a person or organization. Port comparisons can use the latest per-IP target-port metadata; read the displayed coverage notes.

## Installation and safe updates

These component sources are part of the **coordinated KeenTool suite**. Install the complete package from [KeenTool releases](https://github.com/mattheweli/KeenTool/releases/latest); the shared runtime, security broker, authentication and assets are required. Copying an isolated script over an older installation is not a supported upgrade.

On an existing supported installation:

```sh
/opt/bin/bash /opt/bin/keentool --check-updates
/opt/bin/bash /opt/bin/keentool --update
```

KeenTool's **Check all updates** lists each component independently. A tool's **Install / Update** checks its version, all owned files and shared dependencies against verified SHA-256 hashes and permissions. It reports missing/modified files even when the declared version is current. Review the proposed coordinated installation before confirming the archive download. Configuration, credentials, cron schedules and databases are preserved by the normal transaction-backed upgrade; the printed backup supports file rollback.

For a new router or a legacy/alpha migration, follow the complete [installation guide](https://github.com/mattheweli/KeenTool/blob/main/suite/docs/INSTALL.md). Fresh-install web/logging adoption is explicit: review it before replacing an existing listener or logging pipeline. Use `/opt/bin/bash`, root and Entware mounted at `/opt`. Dependencies are checked before installation; `--install-deps` explicitly permits installing missing Entware packages. No general `opkg upgrade` is performed by the suite updater.

## Configure and verify

Use KeenTool → **Firewall Suite** → **Run Manager**, or:

```sh
/opt/bin/bash /opt/bin/firewall_manager.sh
/opt/bin/bash /opt/bin/firewall_monitor
/opt/bin/bash /opt/bin/firewall_health
```

Review `/opt/etc/firewall.conf` and management bypasses before enabling protection. To apply the current hook explicitly after reviewing settings:

```sh
table=filter /opt/bin/bash /opt/etc/ndm/netfilter.d/100-firewall.sh
/opt/bin/bash /opt/bin/firewall_health
```

The upgrade installer does not apply firewall rules automatically. Set the shared administrator password from KeenTool or `firewall_admin_password`. Mutating controls require administrator login; status and allowed diagnostic/log reads remain consultative.

## Data and scheduled jobs

| Item | Location / action |
|---|---|
| Main configuration | `/opt/etc/firewall.conf` |
| Statistics database | `/opt/etc/firewall_stats.db` |
| Web dashboard | `/opt/var/www/firewall/index.html` |
| Saved lists | `/opt/etc/firewall_*.save` |
| List update state | `/opt/etc/keentool/security/lists.json` |
| Regenerate statistics | `/opt/bin/bash /opt/bin/firewall_stats.sh force` |

Existing schedules are preserved. A new suite installation provides a five-minute statistics job and nightly blocklist updates; review them in KeenTool. The NFLOG/PCAP pipeline depends on ulogd and matching native configuration/modules.

## Database size and historical aggregation

Default policy: raw samples for at least **7 days**, hourly buckets through **30 days**, then daily IP/list buckets. Totals remain exact; older within-bucket timing becomes approximate. Before first aggregation the tool creates and verifies a baseline backup, which occupies space separately from the active DB.

```sh
/opt/bin/bash /opt/bin/firewall_history status
/opt/bin/bash /opt/bin/firewall_history run
/opt/bin/bash /opt/bin/firewall_stats.sh force
```

Configure through **History aggregation settings** or authenticated Web Settings. Read the [precision and backup limitations](https://github.com/mattheweli/KeenTool/blob/main/suite/docs/FIREWALL_HISTORY.md). Re-running cannot reconstruct detail already aggregated.

## Feed failures

GeoIP prefix-count changes are not address-coverage changes. Significant nightly changes can be normal. Failed sources may use a validated previous cache; incomplete candidates without a valid cache are rejected and the installed list is retained. For example, an IPdeny IPv6 country endpoint may return HTTP 404. Security & Health and notification summaries report the reason rather than silently removing the configured country.

## Troubleshooting and support

Include the installed suite/component versions, router/Entware architecture, exact command and relevant sanitized output when reporting an issue. Never post passwords, authentication cookies, SMTP credentials or your database.

- [Installation / migration](https://github.com/mattheweli/KeenTool/blob/main/suite/docs/INSTALL.md)
- [Update and repair behavior](https://github.com/mattheweli/KeenTool/blob/main/suite/docs/UPDATE_RECOVERY.md)
- [Backup and rollback](https://github.com/mattheweli/KeenTool/blob/main/suite/docs/ROLLBACK.md)
- [Security and known limitations](https://github.com/mattheweli/KeenTool/blob/main/suite/SECURITY.md)
- [Component versions and changelog](https://github.com/mattheweli/KeenTool/blob/main/suite/VERSIONS.md)

Screenshots are generated from the current application templates with **synthetic documentation data**. They are examples, not live router output or evidence of a real attack/backup. [Reproduce the screenshots](https://github.com/mattheweli/KeenTool/blob/main/suite/docs/demo/README.md).

Created and maintained by **mattheweli**. The repository's existing LICENSE applies. Optional project support: [PayPal](https://paypal.me/MatteoRosettani) · [Revolut](https://revolut.me/matthew_eli).
