## Verdict

Exploitable. Confidence: high.

- CWE: CWE-89 (SQL Injection)
- Location: `LegacyReportRepository.cs`, line 20 (`adapter.Fill(table)`), built from the query string assembled at line 17
- Source: the `region` route/query parameter on `LegacyReportController.Customers([FromQuery] string region)` (line 17 of the controller), passed unmodified (only a `?? ""` null guard) into `LoadCustomers`
- Sink: `SqlDataAdapter.Fill(DataTable)`, executing a `SELECT` built by directly concatenating `region` into the `WHERE` clause

## Source

```csharp
[HttpGet("customers")]
public IActionResult Customers([FromQuery] string region)
{
    var table = _repository.LoadCustomers(region ?? "");
    return Ok(table);
}
```

`region` is caller-controlled via the query string and reaches `LoadCustomers` with no validation or encoding - only a null-to-empty-string substitution, which does not constrain its content.

## Fix

Vulnerable code (`LegacyReportRepository.cs`):

```csharp
public DataTable LoadCustomers(string region)
{
    // VULNERABLE: region is concatenated directly into the SQL string
    var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = '" + region + "'";
    using var adapter = new SqlDataAdapter(sql, _connectionString);
    var table = new DataTable("Customers");
    adapter.Fill(table);
    return table;
}
```

Fixed code:

```csharp
public DataTable LoadCustomers(string region)
{
    const string sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @Region";
    using var connection = new SqlConnection(_connectionString);
    using var command = new SqlCommand(sql, connection);
    command.Parameters.Add("@Region", SqlDbType.NVarChar).Value = region;
    using var adapter = new SqlDataAdapter(command);
    var table = new DataTable("Customers");
    adapter.Fill(table);
    return table;
}
```

## Explanation

The query text now uses the placeholder `@Region` instead of a spliced-in literal, and `region` is bound as the `.Value` of an explicitly typed `SqlParameter` (`SqlDbType.NVarChar`, no size given so the driver sizes it from the runtime value rather than risking truncation) instead of being embedded in the SQL string. The database now always treats `region` as a single data value for the `Region` column comparison, never as query syntax, so a value such as `' OR '1'='1` or one containing a literal quote can no longer alter the query's structure. Because `SqlDataAdapter` cannot take a `SqlCommand` and a raw connection string in the same overload, the fix constructs an explicit `SqlConnection` and `SqlCommand` and passes the command to `SqlDataAdapter`'s command-based constructor; `SqlDataAdapter.Fill` still opens the connection if it is closed and closes it again afterward when it was the one to open it, matching the original constructor's behavior.

## Behaviour changes

- Connection lifecycle: replaced the `SqlDataAdapter(sql, connectionString)` convenience constructor, which creates and manages its own `SqlConnection` internally, with an explicit `SqlConnection` + `SqlCommand` passed to `SqlDataAdapter(IDbCommand)`. `Fill` still opens the connection if it is closed and closes it again afterward under the same conditions as before, so the observable open/close behavior is unchanged; this is required because the `SqlDataAdapter` constructor overload has no parameterized-query equivalent.
- Query text: the literal-embedded `WHERE Region = '...'` became `WHERE Region = @Region`. This is the fix itself, not incidental.
- Input handling: a `region` value containing a single quote or SQL syntax previously altered the query (or threw a SQL syntax error); it is now always treated as a literal comparison value against the `Region` column - values that previously matched no row, or broke the query, now correctly match rows literally equal to that string. This is the intended effect of closing the injection.
- Return value, method signature, and callers: unchanged. No other argument, return type, or discarded output was introduced.
