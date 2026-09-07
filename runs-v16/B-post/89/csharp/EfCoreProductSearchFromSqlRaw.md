## Verdict

Exploitable. The SearchAsync method interpolates user-supplied parameters directly into a SQL string, then passes it to FromSqlRaw without parameterization. An attacker controlling tenantId or term can inject SQL to bypass the WHERE clause and access data from other tenants.

## Source

SearchAsync method parameters `tenantId` and `term` (line 14), both user-controlled and untrusted.

## Fix

**Vulnerable code (line 14-17):**
```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.List<Product>> SearchAsync(string tenantId, string term)
{
    var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'";
    return _db.Products.FromSqlRaw(sql).ToListAsync();
}
```

**Fixed code:**
```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.List<Product>> SearchAsync(string tenantId, string term)
{
    var searchTerm = $"%{term}%";
    return _db.Products.FromSql($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {searchTerm}").ToListAsync();
}
```

## Explanation

The vulnerability was that FromSqlRaw executes a raw SQL string without parameterization, allowing injected SQL syntax to alter query logic. The fix replaces FromSqlRaw with FromSql, which is the parameterizing variant in EF Core 7.0+. When using FromSql with interpolated values, Entity Framework Core automatically wraps each interpolated expression in a DbParameter, ensuring the values are bound as data literals rather than executed as SQL code. The LIKE search pattern construction is moved to C# so the complete pattern (including wildcards) is passed as a single parameter value, preventing any possibility of SQL injection through the search term.

## Behaviour changes

The LIKE search term now includes the wildcard characters at construction time (e.g., if `term` is "product", `searchTerm` becomes "%product%"). All values are now bound as parameters rather than interpolated into the SQL string. Query results and semantics are identical; only the mechanism of parameter binding changes from unsafe string interpolation to safe parameterized queries.
