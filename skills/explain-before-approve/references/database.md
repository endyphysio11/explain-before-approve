# Database and SQL actions

## Operation levels

- Treat `SELECT` as LOW when it only reads data; note possible sensitive output when relevant.
- Treat `INSERT` and bounded `UPDATE` or `DELETE` as MODERATE when the environment is unknown.
- Treat unbounded `UPDATE` or `DELETE`, `ALTER`, `DROP`, `TRUNCATE`, and migrations as HIGH when the environment is unknown.
- Treat visible known-production destructive operations as CRITICAL when they broadly remove data or schema.

## Context

Never infer production, staging, local, backups, replicas, or transaction state. State that the command affects whichever database the client is connected to when the target is unknown.

## Recovery

Transactions may allow rollback before commit. After commit, recovery may require a compensating operation, point-in-time recovery, or a verified backup. Never claim those mechanisms exist without evidence.

## Safer steps

Recommend confirming the connection target, running an equivalent `SELECT`, adding a narrow `WHERE`, starting a transaction, reviewing a migration plan, and verifying a tested backup before destructive schema operations.
