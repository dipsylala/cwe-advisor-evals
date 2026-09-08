## Verdict

CONFIRMED: SQL injection vulnerability in ledgerRepository.js line 10.

The `filters.table` parameter is user-controlled (originating from `req.query.ledger` in the controller) and is directly interpolated into the SQL query string without validation. This allows an attacker to inject arbitrary SQL by passing a malicious table name.

## Source

**Call chain:**
- `ledgerController.js` line 18: `table: req.query.ledger || 'ledger_entries'` - accepts untrusted user input
- `ledgerService.js` line 5: passes `filters` unchanged to `findLedgerRows`
- `ledgerRepository.js` line 6-8: interpolates `filters.table` directly into SQL string
- `ledgerRepository.js` line 10: `prisma.$queryRawUnsafe(sql, ...)` executes the unsafe query

The vulnerability is triggered when a user provides a malicious value for the `ledger` query parameter, such as `ledger_entries; DROP TABLE users; --`, which gets embedded into the SQL query.

## Fix

### File: ledgerRepository.js

```javascript
'use strict';

async function findLedgerRows(prisma, filters) {
  // Allowlist of valid table names
  const validTables = ['ledger_entries', 'archive_ledger_entries', 'pending_ledger_entries'];
  
  // Validate table name against allowlist
  if (!validTables.includes(filters.table)) {
    throw new Error(`Invalid table name: ${filters.table}`);
  }

  const sql = `
    SELECT id, status, amount_cents
    FROM ${filters.table}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRaw(sql, filters.accountId, filters.status);
}

module.exports = { findLedgerRows };
```

## Explanation

The fix introduces two key security controls:

1. **Allowlist validation**: The `validTables` array defines the only table names that are permitted. Any other value is rejected with an error, preventing injection of arbitrary table names.

2. **API change consideration**: While Prisma's `$queryRaw` still cannot parameterize table names, the allowlist ensures only known tables can be referenced. The parameter placeholders for `filters.accountId` and `filters.status` remain safely parameterized through the second and third arguments to `$queryRaw`.

This prevents the injection vulnerability because an attacker cannot bypass the allowlist - they can only select from the predefined set of tables. The allowlist should be maintained by the development team and only include tables that are actually used by the application.
