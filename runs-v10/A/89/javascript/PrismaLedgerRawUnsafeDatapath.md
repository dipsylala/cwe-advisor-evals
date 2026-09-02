## Verdict

The finding is confirmed. The code on line 10 of ledgerRepository.js uses `prisma.$queryRawUnsafe()` with an SQL query that directly interpolates `filters.table` via template literal (`FROM ${filters.table}`) without any validation or escaping. The table name originates from user input (`req.query.ledger`) in the controller, allowing SQL injection.

## Source

The vulnerability flows through three files:

1. **Controller (ledgerController.js, line 9)**: User input `req.query.ledger` is assigned directly to `filters.table` without validation.
2. **Service (ledgerService.js, line 6)**: Filters object is passed through unchanged.
3. **Repository (ledgerRepository.js, line 6 and 10)**: The unvalidated `filters.table` is concatenated into the SQL string via template literal on line 6 (`FROM ${filters.table}`), then executed by `prisma.$queryRawUnsafe()` on line 10.

An attacker can supply a malicious value like `ledger_entries; DROP TABLE users; --` via the `ledger` query parameter to execute arbitrary SQL commands.

## Fix

Implement a whitelist of allowed table names and validate the input before use:

```javascript
async function findLedgerRows(prisma, filters) {
  // Whitelist allowed table names
  const allowedTables = ['ledger_entries', 'ledger_archive', 'ledger_pending'];
  
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

Alternatively, refactor to avoid dynamic table names entirely by using Prisma's type-safe APIs with multiple query methods, one per table, or by restructuring the data model to use a single table with a type column.

## Explanation

Table names cannot be parameterized in SQL—the `?` placeholders on lines 7 safely handle `accountId` and `status`, but table names must be handled differently. The fix validates `filters.table` against a whitelist of legitimate table names before interpolation, ensuring only application-controlled values can be used in the query. This prevents an attacker from injecting SQL by manipulating the `ledger` query parameter. The whitelist should contain only tables that the application is designed to query and should be maintained when new tables are added to the schema.
