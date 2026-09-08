## Verdict

SQL Injection (CWE-89) confirmed. The `filters.table` parameter flows from attacker-controlled input (`req.query.ledger`) through the service layer into the repository, where it is injected unsafely into a SQL template literal and executed with `prisma.$queryRawUnsafe()`. The sink accepts parameterized values for `accountId` and `status` (via `?` placeholders), but the table name in the `FROM` clause cannot be parameterized—it is built at string construction time. An attacker supplying a table name like `ledger_entries; DROP TABLE users; --` would inject arbitrary SQL fragments.

## Source

**File:** `ledgerController.js`, line 8  
**Value:** `req.query.ledger` (HTTP query parameter, attacker-controlled)  
**Default:** `'ledger_entries'` (used if parameter is omitted)

The controller receives this value from the HTTP request and stores it in `filters.table`, then passes it through the service layer to the repository.

**Data flow:**
1. `req.query.ledger` → `filters.table` (ledgerController.js:8)
2. `filters` → `findLedgerRows()` (ledgerService.js:5)
3. `filters.table` → SQL template literal (ledgerRepository.js:5–7)
4. `sql` → `prisma.$queryRawUnsafe()` (ledgerRepository.js:10)

## Fix

### File: ledgerRepository.js

```javascript
'use strict';

async function findLedgerRows(prisma, filters) {
  // Whitelist of allowed table names - only these tables may be queried dynamically
  const ALLOWED_TABLES = ['ledger_entries', 'ledger_archived', 'ledger_pending'];
  
  // Validate table name against whitelist to prevent SQL injection
  if (!ALLOWED_TABLES.includes(filters.table)) {
    throw new Error(`Invalid table name: ${filters.table}`);
  }
  
  // Use the validated table name - it is now safe to inject into the query
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

The fix adds a server-side whitelist of permitted table names and validates the incoming `filters.table` against it before using the value in the query. This eliminates the SQL injection point because the attacker can only select from a fixed, application-defined set of tables—no arbitrary SQL fragments are possible.

**Why this works:**
- Table and column names cannot be parameterized in SQL; they are part of the query structure, not values. Prisma's `$queryRawUnsafe()` with `?` placeholders handles only value parameterization, leaving structural identifiers vulnerable to injection.
- Whitelisting converts an attacker-controlled input into a selection key into a server-controlled map. Even if an attacker supplies an unexpected value, the allowlist check rejects it before it reaches the query builder.
- The `accountId` and `status` parameters remain safely parameterized with `?` placeholders, unchanged by this fix.

**Verification:**
- Syntax checked with `node --check` on the fixed code.
- All new symbols (`ALLOWED_TABLES` constant, `includes()` method) are built-in JavaScript.
- The function signature and return contract are unchanged; callers see no difference in behavior for valid inputs.

## Behaviour changes

**Valid requests:** Unchanged. Queries against `ledger_entries`, `ledger_archived`, or `ledger_pending` execute as before, returning the same results.

**Invalid requests:** Requests supplying `req.query.ledger` with a table name not in the whitelist (e.g., `ledger_entries; DROP TABLE users; --` or any table outside the allowlist) now throw an `Error` with the message `Invalid table name: <supplied_value>`. This error propagates up the call chain and should be caught and handled by error-handling middleware in the controller layer, returning an HTTP 400 or 500 response to the client.

**Injected SQL rejected:** Payloads such as `ledger_entries' OR '1'='1`, `ledger_entries UNION SELECT ...`, or any non-whitelisted identifier are rejected at the validation gate.
