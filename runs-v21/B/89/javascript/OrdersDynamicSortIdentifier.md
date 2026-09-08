## Verdict

The finding is valid. Untrusted query parameters (`sortColumn` and `direction`) are concatenated directly into the SQL query string at line 8 via template literal interpolation, bypassing parameterization and allowing SQL injection.

## Source

HTTP request query parameters `req.query.sort` and `req.query.dir` in orderController.js flow as function parameters into orderRepository.js `findOrders()`.

## Fix

Replace the vulnerable template literal interpolation with strict allowlist validation. Values that cannot be parameterized (column names, identifiers, and `ORDER BY` direction keywords) must be validated against a fixed set of permitted values before use in the query.

### File: orderRepository.js

```javascript
'use strict';

// Allowlist of permitted sort columns
const PERMITTED_SORT_COLUMNS = {
  'id': 'id',
  'total_cents': 'total_cents',
  'status': 'status',
  'created_at': 'created_at',
};

// Allowlist of permitted directions
const PERMITTED_DIRECTIONS = {
  'ASC': 'ASC',
  'DESC': 'DESC',
};

async function findOrders(db, accountId, sortColumn, direction) {
  // Validate sortColumn against allowlist
  if (!PERMITTED_SORT_COLUMNS[sortColumn]) {
    throw new Error(`Invalid sort column: ${sortColumn}`);
  }
  const validatedSortColumn = PERMITTED_SORT_COLUMNS[sortColumn];

  // Validate direction against allowlist
  if (!PERMITTED_DIRECTIONS[direction]) {
    throw new Error(`Invalid direction: ${direction}`);
  }
  const validatedDirection = PERMITTED_DIRECTIONS[direction];

  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${validatedSortColumn} ${validatedDirection}`,
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
```

## Explanation

The original code built the `ORDER BY` clause by directly interpolating untrusted `sortColumn` and `direction` parameters into the SQL string. SQL injection protection via parameterization does not apply to structural elements like column names and keywords—these must be restricted to a fixed set of permitted values.

The fix introduces allowlists mapping safe identifiers to their canonical forms. Untrusted input is validated against these allowlists before being used; if validation fails, an error is thrown immediately. Only the canonical values from the allowlists reach the query, ensuring that even if an attacker provides malicious input like `"created_at; DROP TABLE orders--"`, it will be rejected and the query will not execute. The `accountId` parameter continues to use mysql2's `?` placeholder mechanism, which remains the appropriate protection for actual data values.

## Behaviour changes

- Invalid `sortColumn` or `direction` values now throw an error instead of being concatenated into the query. This prevents SQL injection but breaks existing calls that pass invalid values; the API becomes stricter.
- The query now always uses only the permitted columns and directions defined in the allowlists, eliminating the ability to sort by arbitrary columns.
- Error responses to the caller (orderController.js) will receive the thrown error instead of potentially malicious query results.
