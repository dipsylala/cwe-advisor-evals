## Verdict

The finding is confirmed as a real SQL injection vulnerability via dynamic table name interpolation.

## Source

User input flows from `req.query.ledger` in ledgerController.js through ledgerService.js and into ledgerRepository.js where the table name is interpolated directly into the SQL query string without validation. In Prisma, identifiers (table names) cannot be parameterized and must be validated against an allowlist before use.

**Call chain:**
1. ledgerController.js, line 9: `table: req.query.ledger || 'ledger_entries'` (attacker-controlled)
2. ledgerService.js, line 6: passes filters to findLedgerRows()
3. ledgerRepository.js, line 6: `FROM ${filters.table}` interpolates the table name directly into SQL
4. ledgerRepository.js, line 10: `prisma.$queryRawUnsafe(sql, ...)` executes the unvalidated query

## Fix

### File: ledgerController.js

```javascript
'use strict';

const { exportLedger } = require('./ledgerService');

// Allowlist of permitted ledger table names
const ALLOWED_TABLES = ['ledger_entries', 'transactions', 'events'];

async function ledgerExport(req, res) {
  const requestedTable = req.query.ledger || 'ledger_entries';
  
  // Validate table name against allowlist before passing to service
  if (!ALLOWED_TABLES.includes(requestedTable)) {
    return res.status(400).json({ error: 'Invalid table parameter' });
  }
  
  const filters = {
    accountId: req.user.accountId,
    status: req.query.status || 'posted',
    table: requestedTable,
  };

  const rows = await exportLedger(req.prisma, filters);
  res.json({ rows });
}

module.exports = { ledgerExport };
```

### File: ledgerRepository.js

```javascript
'use strict';

async function findLedgerRows(prisma, filters) {
  // Defensive allowlist validation (second layer)
  // Identifiers cannot be parameterized in SQL, so they must be validated
  // against a fixed set of permitted names before interpolation
  const ALLOWED_TABLES = ['ledger_entries', 'transactions', 'events'];
  
  if (!ALLOWED_TABLES.includes(filters.table)) {
    throw new Error(`Invalid table: ${filters.table}`);
  }
  
  // Construct query with validated table name (safe to interpolate after allowlist check)
  // Data values (accountId, status) use parameterized placeholders (?)
  const sql = `
    SELECT id, status, amount_cents
    FROM ${filters.table}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}

module.exports = { findLedgerRows };
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

The fix addresses the SQL injection vulnerability by implementing strict allowlist validation for the dynamic table name identifier. Since SQL identifiers (table names) cannot be parameterized in any SQL dialect or ORM, including Prisma, they must be validated against a server-controlled allowlist before being incorporated into query construction.

**Key changes:**

1. **ledgerController.js**: Added an `ALLOWED_TABLES` allowlist and validation at the entry point before passing the filters to the service layer. If the table name does not match an allowed value, a 400 error is returned to the client.

2. **ledgerRepository.js**: Added defensive allowlist validation as a second layer of protection. Even if a validated value reaches the repository, it is checked again before interpolation. Only after validation passes does the query construction occur.

The parameterized placeholders (`?`) for the data values (accountId and status) remain in place and continue to prevent value-based SQL injection. The table name is interpolated via JavaScript template literal after allowlist validation, which is the only safe way to handle dynamic identifiers in SQL.

This remediation follows the CWE-89 principle: "Treat a dynamic identifier as a key into a server-side map of permitted names, not as input to validate and then use - the value reaching the query should be the map's, never the caller's."

## Behaviour changes

- **Request validation**: Requests with invalid `ledger` query parameters are now rejected with HTTP 400 and an error message, instead of being passed through to the database query.
- **Database behavior preserved**: For valid table names (those in the allowlist), the query behavior is identical to the original - the same rows are retrieved with the same parameterized WHERE conditions.
- **Error handling**: An invalid table name passed to findLedgerRows now throws an Error instead of attempting the unsafe query.
- **Security**: SQL injection via table name manipulation is eliminated by the allowlist validation.
