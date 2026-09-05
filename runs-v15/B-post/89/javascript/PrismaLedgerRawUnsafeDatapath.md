## Verdict

Exploitable. User-controlled input `req.query.ledger` flows through `filters.table` directly into the SQL query string at line 10 via template literal interpolation, and the table name is executed without allowlist validation. An attacker can inject arbitrary SQL.

## Source

`req.query.ledger` (ledgerController.js line 7) — user-supplied query parameter passed directly into `filters.table` without validation.

## Fix

**Vulnerable code (ledgerRepository.js, lines 3-10):**

```javascript
async function findLedgerRows(prisma, filters) {
  const sql = `
    SELECT id, status, amount_cents
    FROM ${filters.table}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}
```

**Fixed code:**

```javascript
async function findLedgerRows(prisma, filters) {
  const ALLOWED_TABLES = {
    ledger_entries: 'ledger_entries',
    ledger_transactions: 'ledger_transactions',
    archived_ledger: 'archived_ledger'
  };

  const tableName = ALLOWED_TABLES[filters.table];
  if (!tableName) {
    throw new Error(`Invalid table name: ${filters.table}`);
  }

  const sql = `
    SELECT id, status, amount_cents
    FROM ${tableName}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}
```

## Explanation

The fix introduces an allowlist (`ALLOWED_TABLES`) of permitted table names at the repository layer. Rather than using the raw user-supplied `filters.table` in the query, the code validates it against the allowlist and substitutes the canonical value from the map. If the input does not match a permitted table, the function throws an error, preventing injection. This follows the guidance principle: "Treat a dynamic identifier as a key into a server-side map of permitted names, not as input to validate and then use." The parameterized parameters (`accountId`, `status`) remain unchanged, and the overall query contract is preserved.

## Behaviour changes

None. The function signature, return type, error handling behavior, and successful query execution remain identical. The only change is the addition of validation that rejects invalid table names before query execution. Error behavior: now throws `Error` with a descriptive message for invalid table names; the original would have thrown a SQL syntax error later. This is an improvement because it fails fast with a clear message rather than a cryptic database error.
