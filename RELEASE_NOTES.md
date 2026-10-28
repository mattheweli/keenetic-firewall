# keenetic-firewall 4.0.6

Explicit balanced maintenance now guarantees a fresh verified backup when the database is already compact. A conversion backup is reused only within the same invocation; an earlier history/normalization backup is not a current recovery copy. Regression fixtures verify first and repeated balanced runs and the current rows in the latest backup.

Includes the optional compact IP dictionary, balanced 2/7/365-day history and shared lossless Ping/vnStat maintenance from 4.0.5. Installation preserves databases/settings until maintenance is explicitly requested. Update through coordinated package 2.0.17 and review docs/DATABASE_STORAGE.md. Database engine 1.0.1; Stats remains 4.0.2, manager 2.0.11 and other tools unchanged. Old temporal precision cannot be restored by expansion or code rollback.
