## Verdict

SQL injection vulnerability in dynamic table name interpolation. The table name is directly embedded in the SQL string via template literal without validation, allowing an attacker to inject arbitrary SQL commands.

## Source

The vulnerable code directly interpolates `filters.table` into the SQL query string:

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

The `$queryRawUnsafe()` method only parameterizes the `?` placeholders (filters.accountId and filters.status), but the table name in `${filters.table}` is unsanitized. An attacker controlling `filters.table` can inject SQL such as `accounts; DROP TABLE users; --` to execute arbitrary commands.

## Fix

Validate the table name against an allowlist of permitted tables before using it in the query:

```javascript
async function findLedgerRows(prisma, filters) {
  const allowedTables = ['ledger_entries', 'transaction_log', 'account_history'];
  
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

Alternatively, use Prisma's parameterized `$queryRaw()` with template tagging (which handles parameter escaping automatically) and still validate the table name:

```javascript
async function findLedgerRows(prisma, filters) {
  const allowedTables = ['ledger_entries', 'transaction_log', 'account_history'];
  
  if (!allowedTables.includes(filters.table)) {
    throw new Error('Invalid table name');
  }
  
  return prisma.$queryRaw`
    SELECT id, status, amount_cents
    FROM ${Prisma.raw(filters.table)}
    WHERE account_id = ${filters.accountId} AND status = ${filters.status}
  `;
}
```

## Explanation

Table names and database identifiers cannot be parameterized in SQL (unlike data values), so they must be validated against a strict allowlist. The fix ensures only trusted, pre-approved table names are used in the query, preventing injection attacks. The `$queryRawUnsafe()` method name itself signals that raw SQL should only be used with trusted input.
