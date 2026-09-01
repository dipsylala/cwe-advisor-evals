## Verdict

True positive. The code constructs a raw SQL query using string interpolation with unsanitized user input (`tenantId` and `term`), enabling SQL injection.

## Source

Line 16 constructs an SQL query via string interpolation:
```
var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'";
```

Both `tenantId` and `term` parameters flow directly into the query string without parameterization. An attacker can close the quoted string and inject arbitrary SQL code. For example, `term = "' OR '1'='1"` would modify the query logic.

## Fix

Replace `FromSqlRaw()` with `FromSqlInterpolated()` to enable automatic parameterization:

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.List<Product>> SearchAsync(string tenantId, string term)
{
    return _db.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {'%' + term + '%'}").ToListAsync();
}
```

The key changes:
- Replace `FromSqlRaw()` with `FromSqlInterpolated()`
- Remove quotes around interpolated values; `FromSqlInterpolated()` automatically creates SQL parameters
- Remove manual string concatenation for the LIKE pattern; construct it in C# instead

## Explanation

`FromSqlInterpolated()` treats each interpolated expression as a parameter placeholder, automatically parameterizing the query and preventing injection. User input flows as parameter values, not as part of the SQL syntax. This is the standard EF Core defense against SQL injection in dynamic queries.

