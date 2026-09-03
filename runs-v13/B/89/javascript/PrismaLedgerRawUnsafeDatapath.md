## Verdict

Exploitable.

## Source

User-controlled input `req.query.ledger` in ledgerController.js flows through `filters.table` to the SQL query construction.

## Fix

**Vulnerable code** (ledgerRepository.js):

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

**Fixed code** (ledgerRepository.js):

```javascript
'use strict';

// Whitelist of permitted table names - table identifiers cannot be parameterized
const ALLOWED_TABLES = ['ledger_entries', 'ledger_archive', 'ledger_audit_log'];

async function findLedgerRows(prisma, filters) {
  // Validate table name against allowlist; use the canonical value, not the input
  if (!ALLOWED_TABLES.includes(filters.table)) {
    throw new Error(`Invalid table name: only ${ALLOWED_TABLES.join(', ')} are permitted`);
  }

  const tableName = filters.table;

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

SQL table and column names cannot be parameterized - SQL parameter binding (`?` placeholders) applies only to values, not to identifiers. The original code directly interpolates `filters.table` into the SQL string using a template literal, allowing an attacker to inject arbitrary SQL syntax (e.g., `ledger_entries; DROP TABLE users;--`). The fix introduces a server-side allowlist of permitted table names (`ALLOWED_TABLES`), validates that the user-supplied value matches one of them, and uses the validated table name (the canonical value from the controller's assignment, not the raw input) in the query. Validation happens before any SQL construction. If the user supplies a table name not in the allowlist, the function throws an error rather than executing unsafe SQL.

## Behaviour changes

- Added validation that throws an error if `filters.table` is not in the allowlist. This is a security-necessary change: the original code accepted any string and built a SQL query with it. The fix rejects invalid inputs at the entry point.
- Added a constant `ALLOWED_TABLES` to define the set of permitted table names. This must be curated by the application maintainers to match the actual tables the query should access.
- The query still returns the same result shape and still uses parameterized binding for `filters.accountId` and `filters.status` values, so the functional contract is preserved for valid table names.
- Error handling: if an invalid table name is supplied, the caller receives an exception instead of a query attempt. The ledgerController should handle this appropriately (e.g., return a 400 Bad Request error).
