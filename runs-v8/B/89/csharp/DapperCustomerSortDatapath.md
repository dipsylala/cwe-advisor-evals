## Verdict

Exploitable. The `options.Sort` parameter originates from untrusted user input (query string) and is directly string-interpolated into the SQL query without validation or parameterization, allowing SQL injection.

## Source

**Entry point:** `CustomerSearchController.Search()` line 17, `[FromQuery] string? sort` parameter.

**Data flow:** Query string `sort` parameter → `CustomerSearchOptions.Sort` → `CustomerRepository.SearchAsync()` → line 24 SQL interpolation.

## Fix

**Vulnerable code (line 21-26):**
```csharp
var sql =
    "SELECT Id, Name, Status FROM Customers " +
    "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
    $"ORDER BY {options.Sort}";

return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
```

**Fixed code:**
```csharp
// Define allowlist of permitted sort columns
var permittedColumns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
{
    { "Id", "Id" },
    { "Name", "Name" },
    { "Status", "Status" },
    { "created_at", "created_at" }
};

// Validate and resolve sort parameter against allowlist
string sortColumn = permittedColumns.ContainsKey(options.Sort) 
    ? permittedColumns[options.Sort] 
    : "created_at"; // Safe default if sort is invalid

var sql =
    "SELECT Id, Name, Status FROM Customers " +
    "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
    $"ORDER BY {sortColumn}";

return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
```

## Explanation

The original code directly interpolates the untrusted `options.Sort` parameter into the SQL query, allowing an attacker to inject arbitrary SQL. For example, a sort value of `Id; DROP TABLE Customers; --` would execute a destructive query. 

The fix implements an allowlist of permitted sort column names. User input is validated against this allowlist before use, and the matched value from the allowlist is interpolated into the query instead of the original user input. This ensures only known, safe column names can appear in the `ORDER BY` clause. An invalid sort parameter safely defaults to `created_at`. This pattern is necessary because `ORDER BY` column names cannot be parameterized—they must be part of the SQL statement structure, not treated as data values.

## Behaviour changes

**Additional execution:** The allowlist dictionary is created on each method call. If this method is performance-critical and invoked frequently, consider moving the dictionary to a static readonly field to avoid repeated allocation. This is a performance optimization, not a functional change.

**Default sort behavior:** Invalid sort parameters now default to `created_at` rather than being passed through. This is intentional hardening to prevent injection—a client providing an invalid sort parameter will receive results sorted by the safe default instead of a database error or injection.

**No functional regression:** The return type, parameter semantics, and query result set remain unchanged. Legitimate callers with permitted sort values receive identical behavior.
