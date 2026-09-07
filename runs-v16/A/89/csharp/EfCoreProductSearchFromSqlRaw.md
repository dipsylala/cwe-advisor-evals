## Verdict
SQL Injection vulnerability confirmed. The `SearchAsync` method constructs an SQL query using string interpolation without parameterization, allowing attackers to inject arbitrary SQL code through the `tenantId` or `term` parameters.

## Source
Line 16 constructs the raw SQL query by interpolating untrusted input directly into the query string:
```csharp
var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'";
```

Line 17 executes this unparameterized query:
```csharp
return _db.Products.FromSqlRaw(sql).ToListAsync();
```

An attacker can pass `tenantId = "' OR '1'='1"` to bypass tenant isolation or `term = "%' UNION SELECT ...` to extract data.

## Fix
Replace `FromSqlRaw()` with `FromSqlInterpolated()`. Entity Framework Core automatically parameterizes values in interpolated strings passed to `FromSqlInterpolated()`:

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.List<Product>> SearchAsync(string tenantId, string term)
{
    return _db.Products
        .FromSqlInterpolated($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {$"%{term}%"}")
        .ToListAsync();
}
```

Note: Remove the single quotes around `{tenantId}` and the percent signs become part of the literal parameter value passed to the LIKE operator.

## Explanation
`FromSqlRaw()` executes SQL strings exactly as written, with no protection against injection. `FromSqlInterpolated()` treats interpolated values as SQL parameters, which are bound separately from the SQL command structure. The query plan and structure are fixed; attacker-supplied input cannot alter the SQL logic, only the data values being searched. This is the standard parameterized query defense against SQL injection and is built into Entity Framework Core's API design.
