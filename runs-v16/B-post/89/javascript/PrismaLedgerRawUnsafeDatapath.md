## Verdict
exploitable

## Source
`req.query.ledger` parameter in ledgerController.js, line 9, flows through filters.table to the SQL sink

## Fix

**Vulnerable code:**
```javascript
// ledgerRepository.js line 3-11
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
// ledgerRepository.js
async function findLedgerRows(prisma, filters) {
  // Whitelist of allowed table names to prevent SQL injection
  const ALLOWED_TABLES = ['ledger_entries', 'ledger_entries_archive'];
  
  if (!ALLOWED_TABLES.includes(filters.table)) {
    throw new Error(`Invalid table: ${filters.table}`);
  }

  const sql = `
    SELECT id, status, amount_cents
    FROM ${filters.table}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}
```

## Explanation
The vulnerability occurs because `filters.table` is interpolated directly into the SQL template literal on line 6. Although the parameterized values (`account_id` and `status`) are protected via the `?` placeholders passed to `$queryRawUnsafe`, table names cannot be parameterized in SQL—they must be checked against a fixed allowlist before use. An attacker controlling the `ledger` query parameter can inject arbitrary SQL (e.g., `'; DROP TABLE ledger_entries; --`). The fix adds strict whitelist validation that rejects any table name not in the allowed set, ensuring only the validated canonical value reaches the query string. This transforms the untrusted input into a controlled value before it enters the SQL context.

## Behaviour changes
Addition of whitelist validation before SQL execution. The function now throws an `Error` when the table name is not in the allowed list instead of constructing an unsafe SQL query. This is a security-necessary behavior change that prevents exploitation but is a visible change in error handling—invalid table names now fail fast with an explicit error rather than reaching the database. The successful path (valid table names) and return contract remain unchanged.

