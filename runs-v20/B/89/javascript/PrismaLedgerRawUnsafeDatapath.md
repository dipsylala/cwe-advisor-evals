## Verdict

Exploitable. CWE-89 (SQL Injection), confidence: high.

## Source

`req.query.ledger` in `ledgerController.js` (line 9) - an HTTP query-string parameter fully controlled by the caller. It is copied into `filters.table` with only a falsy-value default (`'ledger_entries'`), then passed unchanged through `exportLedger()` (`ledgerService.js`) into `findLedgerRows()`.

Sink: `ledgerRepository.js` line 6/10 - `filters.table` is interpolated directly into the `FROM` clause of the SQL string (`` FROM ${filters.table} ``), and that string is executed via `prisma.$queryRawUnsafe(sql, filters.accountId, filters.status)`.

`filters.accountId` and `filters.status` are not part of this finding: they are passed as separate positional arguments bound to the `?` placeholders, which is the correct parameterized form for `$queryRawUnsafe`. `filters.table`, however, occupies an identifier position (a table name), which placeholders cannot bind - Prisma only parameterizes the values passed after the query string, never text already baked into that string. An attacker who controls `?ledger=` can therefore inject arbitrary SQL by breaking out of the identifier position (e.g. `?ledger=ledger_entries WHERE 1=1; --`, or a subquery/UNION crafted around the fixed `WHERE` clause that follows), altering query structure rather than supplying a value.

## Fix

### File: ledgerRepository.js
```javascript
'use strict';

const ALLOWED_TABLES = {
  ledger_entries: 'ledger_entries',
};

async function findLedgerRows(prisma, filters) {
  const table = ALLOWED_TABLES[filters.table];
  if (!table) {
    throw new Error(`Invalid ledger table: ${filters.table}`);
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

## Explanation

The table name can never be a bound parameter, so the fix treats it as a key into a server-side allowlist instead of as input to sanitize: `ALLOWED_TABLES` maps the only currently-known legitimate value (`ledger_entries`, the codebase's existing default) to itself, and the lookup result - never the raw `filters.table` - is what gets interpolated into the SQL string. Any request for a table not in the map throws before a query is built, so the identifier position can no longer be used to alter query structure. The value-position arguments (`filters.accountId`, `filters.status`) were already passed as separate `$queryRawUnsafe` arguments bound to `?` placeholders and are left untouched, since that already matches the parameterized-query pattern the guidance calls for.

## Behaviour changes

- A request whose `ledger` query parameter is anything other than `ledger_entries` now throws (`Invalid ledger table: <value>`) instead of running a query against that table name. Previously any string reached the `FROM` clause unchecked - not only injection payloads but also references to any other real table the database happened to have, which was itself an authorization gap this repository function had no way to prevent. This assumes `ledger_entries` is the only table the endpoint is meant to serve; the code does not otherwise document or exercise a second legitimate value, so no other table was added to the allowlist. If additional ledger tables are legitimately selectable, they need to be added to `ALLOWED_TABLES` by name.
- An unrecognized table name now surfaces as a thrown `Error` propagating up through `ledgerService.exportLedger()` to `ledgerController.ledgerExport()`, where it is unhandled in the code shown (no try/catch or error middleware is present in these three files) - this is a fail-closed change from silently executing attacker-influenced SQL to rejecting the request, consistent with the sink's existing failure behaviour of throwing on a bad query.
- `filters.accountId` and `filters.status` handling, the `SELECT`/`WHERE` clause shape, and the `$queryRawUnsafe` call signature are unchanged.

## Verification

Copied the fixed file to a scratch location and ran `node --check` against it: passed with no output (syntax valid). No test suite or Prisma schema was available in the case directory to exercise the query at runtime, so behaviour beyond syntax validity was verified by manual trace: `ALLOWED_TABLES[filters.table]` is a plain object property lookup requiring no new imports; `prisma.$queryRawUnsafe`, its argument order, and the `?` placeholder style are unchanged from the original call.

## Assumptions

- `ledger_entries` is assumed to be the only legitimate table this endpoint should query, since it is the only value referenced anywhere in the provided code (the controller's default). No evidence in the three files indicates additional legitimate ledger tables exist; if they do, they must be added to `ALLOWED_TABLES` explicitly.
- The underlying database is assumed to be one that uses `?` positional placeholders (e.g. MySQL) for `$queryRawUnsafe`, consistent with the placeholder style already present in the original, unmodified `WHERE` clause.
