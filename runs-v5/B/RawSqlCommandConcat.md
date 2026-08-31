## Verdict

- **cwe_id**: CWE-89
- **location**: `RawSqlCommandConcat.cs:28` (sink); the vulnerable string build is at line 24
- **verdict**: exploitable
- **confidence**: high

## Source

`owner`, the `[FromQuery] string owner` parameter of `AccountsController.SearchByOwner` (line 19) - an ASP.NET Core model-bound query-string value, fully attacker-controlled with no validation performed on it before use.

Data flow: `owner` (source, line 19) -> concatenated directly into `sql` with `+` (line 24) -> passed unmodified into `new SqlCommand(sql, connection)` (line 25) -> executed at `command.ExecuteReader()` (sink, line 28).

Sink contract:
- **Returns**: a `SqlDataReader` iterated in the `while (reader.Read())` loop to build the anonymous `AccountId`/`Balance` result list.
- **Discards**: nothing beyond the reader itself; no output is currently suppressed.
- **Arguments left implicit**: `ExecuteReader()` is called with no `CommandBehavior` argument (defaults to none) - not security-relevant here since no fix needs to touch it.
- **Failure behaviour**: throws `SqlException` on a malformed or malicious query (e.g. mismatched quotes), which is unhandled by this method and would propagate as a 500. This is unchanged by the fix.

An attacker supplying `owner=' OR '1'='1` turns the query into `WHERE Owner = '' OR '1'='1'`, returning every row in `Accounts` (including `Balance`) regardless of ownership. Because the injected value sits inside a single-quoted string context, closing the quote also enables `UNION SELECT`-based exfiltration of other tables.

## Fix

Vulnerable code (lines 24-28):

```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'";
using var command = new SqlCommand(sql, connection);

// SAST FINDING: CWE-89 reported here. Sink is the next statement.
using var reader = command.ExecuteReader();
```

Fixed code:

```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @owner";
using var command = new SqlCommand(sql, connection);
command.Parameters.AddWithValue("@owner", owner);

using var reader = command.ExecuteReader();
```

## Explanation

The fix replaces string concatenation with a parameterized query: the SQL text now contains the placeholder `@owner` instead of the raw value, and `owner` is bound separately via `SqlCommand.Parameters.AddWithValue`. `AddWithValue` was used instead of `Parameters.Add` with an explicit `SqlDbType` because the target column's declared size/type isn't visible in this file, and guessing a `size` for a `VarChar`/`NVarChar` parameter risks silently truncating legitimate owner names; `AddWithValue` still fully parameterizes the value (SQL Server never interprets its contents as query syntax), which is what closes this finding - the type-inference tradeoff it carries is a plan-stability/performance concern, not a security one. With this change the database driver sends `owner` to SQL Server as a distinct data value in the query's parameter list, so characters like `'`, `--`, or `;` inside it can never alter the query's structure, regardless of content.

## Behaviour changes

- The `sql` string no longer contains the literal `owner` value; it contains a parameter placeholder instead. This is required by the fix and has no observable effect on results for legitimate (non-malicious) input.
- One line added (`command.Parameters.AddWithValue("@owner", owner);`) to bind the parameter; no existing statement was removed, reordered, or had its arguments changed.
- For any `owner` value that previously succeeded in constructing valid SQL (i.e. any value without an embedded `'`), the query result is identical before and after the fix.
- For an `owner` value containing a `'` (previously a malformed-query crash) or SQL metacharacters used to inject additional clauses (previously an unauthorized data disclosure), the fixed code now returns the correct, empty, or single-owner result set (whichever the value legitimately matches) instead of throwing or leaking other accounts' rows - this is the intended elimination of the weakness, not an unrelated behaviour change.
- `ExecuteReader()`'s call signature, return type, and failure behaviour (throwing `SqlException` on error) are unchanged.
