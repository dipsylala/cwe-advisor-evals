## Verdict

SQL injection vulnerability via unvalidated table name interpolation.

## Source

The `filters.table` parameter originates from `req.query.ledger` in `ledgerController.js` (line 9), passed unchecked through the service layer to `ledgerRepository.js`.

## Fix

Validate the table name against an allowlist before interpolating it into the SQL query:

```javascript
async function findLedgerRows(prisma, filters) {
  const allowedTables = ['ledger_entries', 'ledger_archive'];
  
  if (!allowedTables.includes(filters.table)) {
    throw new Error('Invalid table name');
  }
  
  const sql = `
    SELECT id, status, amount_cents
    FROM ${filters.table}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}
```

Alternatively, refactor to use Prisma's query builder methods instead of raw SQL to eliminate the need for identifier interpolation entirely.

## Explanation

The current code directly interpolates `filters.table` into the SQL string (line 6) without validation. While `filters.accountId` and `filters.status` are safely parameterized via the `$queryRawUnsafe()` placeholders, table names cannot be parameterized in SQL — they are structural identifiers, not data values. An attacker can supply a crafted table name via `req.query.ledger` to modify the query structure and extract unauthorized data.

The fix implements a whitelist of allowed table names. Only explicitly approved values are used in the query; all others are rejected. This prevents structural modification of the SQL query while preserving the parameterized protection for the WHERE clause values.
