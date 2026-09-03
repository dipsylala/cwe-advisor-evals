## Verdict

The code is vulnerable to SQL injection.

## Source

Line 16 constructs a raw SQL query using string interpolation with unsanitized user input:

```csharp
var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'";
```

The `tenantId` and `term` parameters are directly embedded in the SQL string without any escaping or parameterization. An attacker can inject SQL metacharacters to modify the query's logic or execute arbitrary SQL commands.

## Fix

Replace `FromSqlRaw()` with `FromSqlInterpolated()`, which automatically parameterizes interpolated values:

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.List<Product>> SearchAsync(string tenantId, string term)
{
    var pattern = $"%{term}%";
    return _db.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {pattern}").ToListAsync();
}
```

`FromSqlInterpolated()` treats interpolated expressions as parameters, not literal SQL text. The values are passed separately to the database driver, preventing injection.

## Explanation

EF Core's `FromSqlRaw()` executes the SQL string exactly as provided, making it unsafe for dynamic values. `FromSqlInterpolated()` is the parameterized alternative: it parses the interpolated string and converts each `{expression}` into a database parameter while keeping the rest as literal SQL.

This eliminates SQL injection because user-supplied values are never treated as executable SQL syntax—they are always passed as data to the database engine.
