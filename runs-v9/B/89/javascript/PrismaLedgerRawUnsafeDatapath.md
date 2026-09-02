## Verdict

CWE-89, exploitable. Confidence: high.

- **Location:** `ledgerRepository.js`, line 10 (the `prisma.$queryRawUnsafe(sql, ...)` call), with the injectable value built at line 6.
- **Sink:** `prisma.$queryRawUnsafe(sql, filters.accountId, filters.status)`.

## Source

`req.query.ledger` in `ledgerController.js` (line 9) - an unauthenticated, attacker-controlled HTTP query parameter, defaulted to `'ledger_entries'` only when absent.

Data flow: `ledgerController.ledgerExport` reads `req.query.ledger` into `filters.table` -> passed unchanged through `ledgerService.exportLedger(prisma, filters)` -> `ledgerRepository.findLedgerRows(prisma, filters)`, where it is interpolated directly into the SQL text via a template literal (`FROM ${filters.table}`) and that string is executed with `prisma.$queryRawUnsafe`.

`filters.accountId` and `filters.status` are not part of the finding - they are passed to `$queryRawUnsafe` as separate positional arguments bound against the `?` placeholders, which Prisma's query engine parameterizes correctly regardless of the underlying provider. The vulnerable element is `filters.table`, which lands in the FROM clause with no parameterization possible, since a table name is an identifier, not a bindable value.

**Sink contract:** `$queryRawUnsafe(query, ...values)` returns a `Promise` resolving to an array of row objects, which the caller `res.json({ rows })`s back unchanged; it throws on a malformed/invalid query, which is not currently caught anywhere in the chain. It takes no arguments beyond the SQL string and the positional bind values - there is no separate identifier-escaping parameter to fall back on.

## Fix

Vulnerable code (`ledgerRepository.js`):

```javascript
async function findLedgerRows(prisma, filters) {
  // filters.table is interpolated straight into the raw SQL string below -
  // it is an attacker-controlled value (req.query.ledger), and a table
  // name cannot be passed as a bound parameter.
  const sql = `
    SELECT id, status, amount_cents
    FROM ${filters.table}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}
```

Fixed code:

```javascript
'use strict';

// Canonical allowlist: only these ledger tables may ever be queried.
// filters.table is looked up here, never used directly.
const ALLOWED_LEDGER_TABLES = new Map([
  ['ledger_entries', 'ledger_entries'],
  ['ledger_entries_archive', 'ledger_entries_archive'],
]);

async function findLedgerRows(prisma, filters) {
  const table = ALLOWED_LEDGER_TABLES.get(filters.table);
  if (!table) {
    throw new Error(`Unsupported ledger table: ${filters.table}`);
  }

  const sql = `
    SELECT id, status, amount_cents
    FROM ${table}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}

module.exports = { findLedgerRows };
```

No library or version recommendation applies here - the fix is a code-level allowlist, not a dependency change; `$queryRawUnsafe` itself remains the right call for this query since Prisma's tagged-template `$queryRaw` cannot parameterize a table name either.

## Explanation

The `FROM` clause table name cannot be bound as a query parameter in any SQL driver, including Prisma's raw-query methods, so the only safe way to accept a caller-influenced table selector is to stop treating the raw string as trusted input and instead use it strictly as a lookup key into a fixed, server-controlled map of permitted table names. The fix resolves `filters.table` through `ALLOWED_LEDGER_TABLES` and uses only the map's canonical value (`table`) in the interpolated SQL string; the original `filters.table` value never reaches the query. Any value not present in the map - including crafted strings such as `ledger_entries; DROP TABLE users; --` or a UNION-based read of another table - is rejected before a query is ever built, closing the injection path while leaving the already-correct parameter binding for `accountId` and `status` untouched.

## Behaviour changes

- A `filters.table` value outside the allowlist now throws synchronously with `Unsupported ledger table: <value>` before any database call is made, instead of reaching `$queryRawUnsafe` (where it would previously execute as attacker-supplied SQL, or fail with a raw database error if merely a typo). Callers such as `ledgerController.ledgerExport` do not currently catch this and will surface it as an unhandled rejection / 500 response - the same place an invalid-table database error would have surfaced before, so overall error-handling posture is unchanged, but the trigger is now explicit validation rather than the database engine.
- The set of allowed tables (`ledger_entries`, `ledger_entries_archive`) is an assumption based on the observed default (`'ledger_entries'`) and common ledger-table naming; it is not derived from a schema or config seen in the provided files. The developer should confirm the complete, legitimate set of ledger tables this endpoint is meant to expose and adjust the map accordingly - too narrow a list breaks a currently-working `?ledger=` value, too broad reintroduces exposure.
- No change to `accountId`/`status` handling, return shape, or the `res.json({ rows })` response contract in `ledgerController.js`.
