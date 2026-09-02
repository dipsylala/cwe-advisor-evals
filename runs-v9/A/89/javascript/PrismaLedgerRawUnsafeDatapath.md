## Verdict
Confirmed. SQL injection via unvalidated identifier interpolation into a raw query.

## Source
`req.query.ledger` (HTTP query parameter) in `ledgerController.js`, assigned to `filters.table` and passed unchanged through `exportLedger()` (`ledgerService.js`) into `findLedgerRows()` (`ledgerRepository.js`).

## Fix

```javascript
'use strict';

const ALLOWED_TABLES = new Set(['ledger_entries', 'ledger_entries_archive']);

async function findLedgerRows(prisma, filters) {
  if (!ALLOWED_TABLES.has(filters.table)) {
    throw new Error(`Invalid ledger table: ${filters.table}`);
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

## Explanation
`filters.table` is attacker-controlled: it flows straight from `req.query.ledger` in `ledgerController.js` through `exportLedger()` with no transformation, and `findLedgerRows()` splices it directly into the `FROM` clause of a SQL string via template literal before handing that string to `prisma.$queryRawUnsafe`. `$queryRawUnsafe` does not parse or parameterize the SQL text itself — it only binds the positional `?` arguments (`accountId`, `status`) that follow it, so those two values are safe, but the table name is concatenated into the query text and executed as-is. A request such as `?ledger=ledger_entries; DROP TABLE users;--` (or a UNION-based read of another table) reaches the database verbatim.

SQL parameter binding cannot substitute for identifiers such as table or column names — placeholders only work for value positions, not for schema names — so this has to be closed with allowlist validation rather than parameterization. The fix resolves `filters.table` against a fixed set of legitimate ledger table names before it ever reaches string interpolation, and rejects the request outright if it doesn't match. The `?`-bound values (`accountId`, `status`) were already handled correctly and are left unchanged. Callers should also update `ledgerController.js` to return a 400 response (rather than letting the thrown error propagate as a 500) when the table name fails validation, so an invalid `ledger` query parameter surfaces as a client error rather than a raw exception.
