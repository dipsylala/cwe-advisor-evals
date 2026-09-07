## Verdict

Exploitable. The `ids` parameter from the function caller is concatenated directly into the SQL query without parameterization, allowing SQL injection.

## Source

`ids` parameter - an array of values passed to the `getOrdersByIds()` function, untrusted and user-controllable.

## Fix

### File: orders.js

```javascript
async function getOrdersByIds(pool, ids) {
  const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');

  const result = await pool.query(`SELECT * FROM orders WHERE id IN (${placeholders})`, ids);
  return result.rows;
}

module.exports = { getOrdersByIds };
```

## Explanation

The vulnerability occurs at line 5 where `ids.join(',')` concatenates untrusted array elements directly into a template literal passed to `pool.query()`. An attacker can inject SQL by crafting the ids array (e.g., `[1, "1) OR (1=1"]`) to break out of the intended WHERE clause and manipulate the query logic.

The fix replaces string concatenation with a parameterized query. It builds placeholders (`$1, $2, $3, ...`) for each element in the `ids` array, then passes the array as the second parameter to `pool.query()`. The PostgreSQL `pg` driver handles parameter binding, ensuring each value is properly escaped and treated as data, not executable SQL. This prevents SQL injection regardless of the values in the `ids` array.

## Behaviour changes

1. **Added `placeholders` variable**: Constructs a string of `$1, $2, ...` placeholders, one per element in `ids`. This variable did not exist in the original code.
2. **Changed `pool.query()` call**: Added a second argument (`ids` array) to pass parameter values to the driver. The original code had no parameters; the fixed code uses parameterized binding. The query string now contains placeholders instead of concatenated values.

Both changes are necessary to close the SQL injection vulnerability. The return value contract is preserved—`result.rows` is still returned unchanged. The fix does not alter error handling or any other side effects of the original code.
