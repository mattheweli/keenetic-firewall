# keenetic-firewall 4.0.3

Hook 3.0.1 participates in the coordinated suite's guarded migration: explicit application consent, IPv4/IPv6 health verification and a fresh SSH challenge. An independent guardian restores previous owned rules, metadata and source if application fails or confirmation is missing. New router-triggered reapplications are blocked while pending; reboot recovery restores previous source before invoking the old hook.

Deferring retains the previous boot hook, including when permanent source backups are declined. Disabled firewalls stay disabled. Foreign router rules, existing bans, credentials, statistics and schedules are preserved. Monitor 4.0.0, Stats 4.0.1 and Manager 3.0.0 keep their versions. The private guard helper source is included for transparency and is installed by the coordinated package, not this component on its own.

## Installation

Install/update KeenTool coordinated package **2.0.14** through KeenTool → u, approve guarded application and type the fresh challenge while SSH remains usable. After upgrading the updater, a deferred migration can be retried with `keentool --update --reinstall --apply-firewall`. Do not copy isolated component files into an older suite: the guarded installer, marker handling and independent recovery copies must ship together. See docs/FIREWALL_UPGRADE.md.

## Validation

The coordinated suite's guardian tests exercise the real hook/helper and real file transactions against a mocked kernel, including confirmation/rejection, independent recovery after parent SIGKILL, failed family/restore paths, foreign-rule/bans retention and reboot recovery. The exact successful coordinated release commit and workflow are recorded in the KeenTool release. Physical-router connectivity/reboot is not inferred from isolated tests.
