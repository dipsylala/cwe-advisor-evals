## Verdict

CONFIRMED - SQL Injection via dynamic sort column and direction

## Source

Function parameters `sortColumn` and `direction` from caller (untrusted).

## Fix

```javascript
'use strict';

async function findOrders(db, accountId, sortColumn, direction) {
  // Allowlist of permitted columns to prevent injection
  const ALLOWED_COLUMNS = {
    'id': 'id',
    'total_cents': 'total_cents',
    'status': 'status',
    'created_at': 'created_at',
  };

  // Allowlist of permitted directions
  const ALLOWED_DIRECTIONS = {
    'ASC': 'ASC',
    'DESC': 'DESC',
  };

  // Validate and select from allowlist - use the validated value, not the original input
  const validatedColumn = ALLOWED_COLUMNS[sortColumn];
  const validatedDirection = ALLOWED_DIRECTIONS[direction];

  if (!validatedColumn || !validatedDirection) {
    throw new Error('Invalid sort column or direction');
  }

  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${validatedColumn} ${validatedDirection}`,
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
```

## Explanation

Column names and ORDER BY direction keywords cannot be parameterized in SQL - they are structural, not data. The vulnerability on line 8 occurs because `sortColumn` and `direction` are directly interpolated into the query using template literals.

The fix replaces direct concatenation with strict allowlist validation. Each input is matched against a server-controlled map of permitted values. Critically, the validated value is selected from the allowlist and used in the query, not the original tainted input. This prevents an attacker from injecting payloads like `sortColumn = "id OR 1=1"` or `direction = "ASC; DROP TABLE orders; --"`.

The `accountId` parameter remains properly parameterized with `?` placeholder, as it is data-only and does not need structural validation.

## Behaviour changes

- Invalid sort column or direction values now throw an error rather than being passed to the database, preventing silent misuse.
- Callers must supply values that exactly match the allowlist keys (`'id'`, `'total_cents'`, `'status'`, `'created_at'`, `'ASC'`, `'DESC'`), reinforcing the contract that only specific orderings are permitted.
