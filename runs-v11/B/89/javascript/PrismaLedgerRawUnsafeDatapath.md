## Verdict

Real SQL injection. The table name is user-controlled and interpolated directly into the query without validation, allowing an attacker to manipulate query structure.

## Source

`ledgerController.js` line 9: `table: req.query.ledger` — user input from the `ledger` query parameter flows directly into filters without validation. Passed through `ledgerService.js` unchanged and into `ledgerRepository.js`.

## Fix

Replace the template literal injection of the table name with a whitelist validation. Only allow known, safe table names. Table names (and column names, `ORDER BY` directions, etc.) cannot be bound as parameters — they must be validated against a fixed set of permitted identifiers before use in the query.

```javascript
async function findLedgerRows(prisma, filters) {
  // Whitelist of allowed tables
  const ALLOWED_TABLES = ['ledger_entries', 'ledger_archive'];
  
  // Validate table name against whitelist
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

The vulnerability occurs because `filters.table` is sourced from untrusted user input (`req.query.ledger`) and interpolated directly into the SQL template at line 6 using `${filters.table}`. Unlike the parameterized values (`accountId` and `status`), table names cannot use placeholders — SQL parameter binding applies only to values, not query structure.

An attacker can inject SQL by submitting a `ledger` parameter such as `ledger_entries; DROP TABLE users; --` to manipulate the query structure. Parameterization alone cannot fix this because database drivers do not allow binding table names.

The fix uses a whitelist to restrict the table name to a fixed set of application-defined values. The whitelist is checked before constructing the query, rejecting any input not in the allowed set. This ensures the table name remains a fixed part of the query structure rather than user-controlled input. The parameterized placeholders for `accountId` and `status` remain in place, protecting those value bindings.

## Behaviour changes

- Queries with a `ledger` parameter outside the whitelist (`['ledger_entries', 'ledger_archive']`) now throw an error instead of executing
- Legitimate queries using allowed tables continue to execute correctly
- The parameterized binding of account ID and status values is preserved, maintaining protection against value-based injection
- Invalid table names are rejected at query time before any database operation occurs
