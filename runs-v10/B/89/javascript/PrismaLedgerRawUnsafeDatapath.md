## Verdict

Confirmed. CWE-89 SQL injection via unvalidated table name interpolation.

## Source

`ledgerController.js` line 9: `table: req.query.ledger || 'ledger_entries'` - untrusted HTTP query parameter flows through `exportLedger()` and `findLedgerRows()` to the database query without validation.

## Fix

Define a whitelist of permitted table names and validate the input against it before interpolation:

```javascript
'use strict';

const ALLOWED_TABLES = {
  ledger_entries: 'ledger_entries',
  ledger_archive: 'ledger_archive',
};

async function findLedgerRows(prisma, filters) {
  const table = ALLOWED_TABLES[filters.table];
  if (!table) {
    throw new Error(`Invalid table name: ${filters.table}`);
  }

  const sql = `
    SELECT id, status, amount_cents
    FROM ${table}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}

module.exports = { findLedgerRows };
```

## Explanation

The vulnerability is at line 6 of the original code: `FROM ${filters.table}` directly interpolates an untrusted value into SQL via template literal. Although `accountId` and `status` are correctly parameterized, table names cannot be parameterized in SQL—they must be validated against a server-controlled allowlist instead.

The fix defines `ALLOWED_TABLES` as a map of permitted table identifiers. When `filters.table` arrives, we validate it by looking it up in the map. If a match is found, we use the canonical value from the map in the query; if not, we throw an error. This ensures that attacker input like `ledger_entries; DROP TABLE users;--` is rejected before it reaches the SQL engine, closing the injection vector while preserving legitimate queries.

The call chain remains unchanged: the same `prisma.$queryRawUnsafe()` call is used with the validated table name and parameterized `accountId` and `status` values.

## Behaviour changes

- Invalid table names now raise an error instead of being passed to Prisma.
- Callers (the service and controller) will need to handle the thrown error, either by catching it locally or allowing it to propagate to their error handler (no change required in those layers if they already handle query errors).
- Only queries matching the whitelist execute successfully; all others fail fast before reaching the database.
