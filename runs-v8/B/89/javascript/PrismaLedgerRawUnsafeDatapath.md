## Verdict

Exploitable.

## Source

User input from `req.query.ledger` in ledgerController.js (line 9) flows untrusted into `filters.table`, which is then passed through the call chain to ledgerRepository.js.

## Fix

**Vulnerable code (ledgerRepository.js, lines 3–11):**

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
  // Whitelist of permitted table names
  const allowedTables = {
    'ledger_entries': 'ledger_entries',
    'transaction_log': 'transaction_log',
    'audit_trail': 'audit_trail'
  };

  // Validate the table name against the allowlist
  const validatedTable = allowedTables[filters.table];
  if (!validatedTable) {
    throw new Error(`Invalid table name: ${filters.table}`);
  }

  const sql = `
    SELECT id, status, amount_cents
    FROM ${validatedTable}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}
```

## Explanation

Table and column identifiers cannot be parameterized in Prisma (or most SQL interfaces), so they must be validated against a server-side allowlist before interpolation. The fixed code defines `allowedTables` as a map of permitted table names. User input from `filters.table` is validated by treating it as a key into this map. Only the canonical value from the allowlist (`validatedTable`) is used in the SQL query. If the input does not match an allowlisted table, an error is thrown immediately, preventing SQL injection. The parameterized values (`filters.accountId` and `filters.status`) already passed as separate parameters to `$queryRawUnsafe()` remain safely bound and are unaffected by this change.

## Behaviour changes

- **Request validation**: The function now rejects requests with table names not in the allowlist, throwing an error with code `Invalid table name: {value}`. Requests that previously succeeded with arbitrary table names will now fail.
- **Allowlist maintenance**: The `allowedTables` map must be updated whenever new tables are added to the schema. This is intentional—keeping the whitelist explicit and server-controlled prevents table name injection.
