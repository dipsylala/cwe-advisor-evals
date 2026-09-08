## Verdict

Confirmed. This is SQL injection (CWE-89).

## Source

`req.query.ledger` in `ledgerController.js` (`ledgerExport`) is attacker-controlled HTTP query input. It flows unvalidated into `filters.table`, is passed through `exportLedger` in `ledgerService.js`, and reaches `ledgerRepository.js`'s `findLedgerRows`, where it is interpolated directly into a SQL string via a template literal (`FROM ${filters.table}`) that is executed with `prisma.$queryRawUnsafe`.

`accountId` and `status` are correctly bound as `?` placeholders, but the table name cannot be parameterized that way — a bind parameter can only stand in for a value, not an identifier — so the raw string concatenation for `filters.table` is a live injection point. A request like `?ledger=ledger_entries; DROP TABLE ledger_entries;--` (or a UNION-based read of other tables) is executed as part of the query.

## Fix

### File: ledgerRepository.js
```javascript
'use strict';

// Known, legitimate ledger tables this endpoint is allowed to read from.
// Extend this set only with real table names from the schema.
const ALLOWED_TABLES = new Set(['ledger_entries']);

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

SQL identifiers (table names, column names) cannot be passed as bind parameters in any SQL driver, including Prisma's `$queryRawUnsafe`/`$queryRaw` — parameter placeholders only substitute values. Since `filters.table` ultimately originates from a query string the client controls, string-interpolating it into the SQL text is unsafe regardless of how it's escaped or quoted, because escaping targets value contexts, not identifier contexts, and any escaping scheme can be bypassed with the right encoding or dialect quirk.

The correct fix is to stop treating the table name as free-form data and instead validate it against a closed set of table names the application actually knows about — a fixed allowlist keyed on the identifier's legitimate values, not a generic input-sanitization pattern. That allowlist is a product decision (which tables this export endpoint is permitted to read), not a superficial security filter, so it belongs at the point where the identifier is consumed. Once `filters.table` is checked to be a member of `ALLOWED_TABLES`, only known-safe literal identifiers ever reach the query string, and the injection point in the `FROM` clause is closed while leaving the existing parameterized `WHERE` clause bindings untouched.

The check throws for anything outside the allowlist rather than silently substituting a default, so an unexpected or malicious value fails loudly instead of being coerced into looking valid. `ledgerController.js` and `ledgerService.js` needed no changes — the vulnerability is entirely in how `ledgerRepository.js` builds and executes the SQL, so the fix is scoped there.
