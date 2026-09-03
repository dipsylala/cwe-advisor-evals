## Verdict

Vulnerable. SQL injection via unsanitized table name parameter.

## Source

In ledgerController.js line 9, the table name is read directly from the user-supplied query parameter:
```
table: req.query.ledger || 'ledger_entries'
```

This untrusted input flows through ledgerService.js and reaches ledgerRepository.js, where it is directly interpolated into the SQL template string at line 6:
```
FROM ${filters.table}
```

Even though Prisma parameterizes the `accountId` and `status` values with `?` placeholders, the table name cannot be parameterized and is concatenated directly into the SQL string at line 6 of ledgerRepository.js.

## Fix

Add a whitelist validation for the table name in `findLedgerRows()` to ensure only authorized tables can be queried:

```javascript
async function findLedgerRows(prisma, filters) {
  const allowedTables = ['ledger_entries', 'audit_log', 'transaction_history'];
  
  if (!allowedTables.includes(filters.table)) {
    throw new Error(`Invalid table name: ${filters.table}`);
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

Table and column identifiers cannot be parameterized in SQL and must be validated if they derive from untrusted input. The fix enforces a strict whitelist of allowed table names before constructing the SQL query. Attempting to use any table outside the whitelist will throw an error, preventing SQL injection attacks that would otherwise permit an attacker to query arbitrary tables or manipulate the query structure.

The whitelist should be maintained to include only the tables that the application legitimately needs to query through this endpoint.
