## Verdict

SQL injection vulnerability confirmed. The `SearchAsync` method constructs an SQL query by concatenating untrusted parameters (`tenantId` and `term`) directly into the query string using string interpolation, then executes it with `FromSqlRaw`. This allows an attacker to inject arbitrary SQL by crafting malicious input.

## Source

**Controller:** `ProductSearchController.cs`, line 20  
**Repository:** `ProductSearchRepository.cs`, line 16–17

The untrusted input `q` flows from the HTTP query string to the controller, which passes it as `term` to `SearchAsync()`. The method then interpolates both `tenantId` (from claims, but still untrusted in a multi-tenant context) and `term` directly into an SQL string:

```csharp
var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'";
return _db.Products.FromSqlRaw(sql).ToListAsync();
```

An attacker can inject SQL by providing input such as `' OR '1'='1` or `%' UNION SELECT ...`.

## Fix

Replace the string interpolation with parameterized query execution using `FromSql()` (EF Core 7.0+) or `FromSqlInterpolated()` (earlier versions). Construct the LIKE pattern as a string value before parameterization so the `%` wildcards are part of the data, not SQL syntax:

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.List<Product>> SearchAsync(string tenantId, string term)
{
    var searchPattern = $"%{term}%";
    return _db.Products.FromSql($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {searchPattern}").ToListAsync();
}
```

Entity Framework Core's `FromSql()` automatically wraps each interpolated value in a `DbParameter`, ensuring they are treated as data values, not SQL code.

## Explanation

The vulnerability exists because `FromSqlRaw()` does not automatically parameterize interpolated values—it concatenates them directly into the SQL string. Even though the code uses a C# string interpolation syntax (`$"...{value}..."`), the values are treated as raw strings, not as parameterized data.

The fix uses `FromSql()` instead of `FromSqlRaw()`, which applies parameterization to each interpolated value. This ensures that:

1. User input is always treated as a value, never as SQL syntax
2. Quote characters, SQL keywords, and other metacharacters in the input are escaped automatically
3. The query structure cannot be altered by the input

For LIKE queries, the pattern string itself (including the `%` wildcards) is pre-constructed and passed as a parameter, so the wildcards become part of the data value being matched, not SQL syntax.

## Behaviour changes

- **Query execution:** Queries now use parameterized execution, which is slightly more efficient than string concatenation and provides a consistent execution plan across runs.
- **Security:** Injection attacks are prevented because user input is always passed as a parameter value, never as part of the query structure.
- **Error handling:** If a malicious or oversized input is provided, the database driver will validate it as a parameter value rather than executing it as SQL, potentially raising parameter validation errors instead of SQL injection.
- **Functional behavior:** Search results remain identical for legitimate input; only malicious injection attempts are now blocked.
