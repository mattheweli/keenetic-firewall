# keenetic-firewall 4.0.4

Fix guardian readiness polling on BusyBox builds which reject fractional sleep. Guardian 1.0.1 uses whole seconds; Hook 3.0.1, Monitor 4.0.0, Stats 4.0.1 and Manager 3.0.0 retain their versions.

The coordinated package 2.0.15 also fixes rollback service handling: leave untouched running vnStat alone, restore verified source despite service errors and report incomplete recovery. A separate SHA-256-verified recover-firewall-upgrade.sh asset restores an interrupted same-boot 2.0.14 transaction through its original pinned guardian. Keep the recovery directory and inspect phase/logs/services; do not retry 2.0.14 over a pending transaction. See the KeenTool 2.0.15 release and docs/FIREWALL_UPGRADE.md. No password reset, database pruning, list replacement or cron change is introduced.

## Installation and validation

Update through KeenTool coordinated package 2.0.15. Do not install isolated component files into an older suite. The suite checks force integer-only sleep and reproduce the exact previous guardian/rollback with an untouched-vnStat stop failure, then exercise the standalone recovery entry with real file operations and mocked service/kernel state. No physical-router recovery is claimed. The historical missing web permission ledger warning is separate and is not repaired by guessing permissions.
