## Verdict
SQL injection via unvalidated table name interpolation. The `$queryRawUnsafe()` call directly interpolates user-supplied `filters.table` into the SQL query string without validation. Although the parameter values (`accountId` and `status`) are safely parameterized, the table identifier is not and cannot be parameterized in SQL, making it a direct injection vector.

## Source
The vulnerability exists in a three-file call chain:
1. **ledgerController.js** (lines 8-9): Accepts `filters.table` from untrusted user input via `req.query.ledger` with no validation
2. **ledgerService.js** (line 6): Passes `filters` through unchanged
3. **ledgerRepository.js** (line 10): Uses `prisma.$queryRawUnsafe(sql, ...)` with string interpolation `${filters.table}` directly into the SQL, where an attacker can inject arbitrary SQL identifiers or expressions

## Fix

### File: ledgerRepository.js
```javascript
'use strict';

const ALLOWED_TABLES = new Set(['ledger_entries', 'ledger_history', 'ledger_archive']);

async function findLedgerRows(prisma, filters) {
  // Validate table name against allowlist
  if (!ALLOWED_TABLES.has(filters.table)) {
    throw new Error(`Invalid table name: ${filters.table}`);
  }

  const sql = `
    SELECT id, status, amount_cents
    FROM ${filters.table}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}

module.exports = { findLedgerRows };
```

### File: ledgerController.js
```javascript
'use strict';

const { exportLedger } = require('./ledgerService');

async function ledgerExport(req, res) {
  const filters = {
    accountId: req.user.accountId,
    status: req.query.status || 'posted',
    table: req.query.ledger || 'ledger_entries',
  };

  const rows = await exportLedger(req.prisma, filters);
  res.json({ rows });
}

module.exports = { ledgerExport };
```

### File: ledgerService.js
```javascript
'use strict';

const { findLedgerRows } = require('./ledgerRepository');

async function exportLedger(prisma, filters) {
  return findLedgerRows(prisma, filters);
}

module.exports = { exportLedger };
```

## Explanation
Table names cannot be parameterized in SQL (only column values can be), so `${filters.table}` must be controlled by the application, not derived from user input. The fix introduces an allowlist of permitted table names and validates the input before constructing the query. Any attempt to inject a table name outside the allowlist (e.g., `ledger_entries; DROP TABLE users--`) will throw an error, blocking the injection.

The parameterized values (`accountId` and `status`) remain properly protected via the `?` placeholders in the prepared statement, which `$queryRawUnsafe()` still honors for parameter positions.

Controller and service files remain functionally unchanged to preserve backward compatibility—the validation is enforced at the repository layer where the query is constructed. The allowlist can be extended or moved to a configuration file as requirements evolve.
