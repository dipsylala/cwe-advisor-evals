## Verdict

SQL injection via dynamic table name parameter. The vulnerability is confirmed and exploitable. An attacker can inject SQL commands by manipulating `req.query.ledger`.

## Source

`req.query.ledger` in ledgerController.js (line 9) - untrusted user input flows into `filters.table`

## Fix

### File: ledgerRepository.js

```javascript
'use strict';

async function findLedgerRows(prisma, filters) {
  // Whitelist permitted table names
  const PERMITTED_TABLES = {
    ledger_entries: 'ledger_entries',
    ledger_history: 'ledger_history',
    audit_log: 'audit_log',
  };

  if (!(filters.table in PERMITTED_TABLES)) {
    throw new Error(`Invalid table name: ${filters.table}`);
  }

  // Use the validated table name from the whitelist, not the original user input
  const tableName = PERMITTED_TABLES[filters.table];

  const sql = `
    SELECT id, status, amount_cents
    FROM ${tableName}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}

module.exports = { findLedgerRows };
```

## Explanation

The original code interpolated `filters.table` directly into the SQL string using a template literal. While `filters.accountId` and `filters.status` were correctly parameterized using `?` placeholders, the table name was not. SQL table and column names cannot be parameterized in any SQL dialect - they are identifiers, not values. The fix validates `filters.table` against a server-side whitelist of permitted table names (`ledger_entries`, `ledger_history`, `audit_log`) and uses only the canonical value from the whitelist in the query. An attacker cannot inject SQL by manipulating the table name because the request value is rejected if it does not match an entry in the allowlist. The value used in the query comes from the application's own map, not from user input.

## Behaviour changes

- The function now rejects requests with invalid table names by throwing an error. This is a necessary behavioural change that prevents injection - requests with `table` values outside the whitelist will fail instead of executing arbitrary SQL.
- No changes to the parameterized query structure for `accountId` and `status` - these remain bound as placeholders.
- Return value and error handling for valid queries are unchanged.
