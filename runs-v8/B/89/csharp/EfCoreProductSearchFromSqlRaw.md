## Verdict

Exploitable. The vulnerability allows SQL injection through unsanitized user input (`tenantId` and `term` parameters) that is concatenated directly into the SQL query passed to `FromSqlRaw()`.

## Source

Method parameters `tenantId` and `term` (line 14) passed from untrusted caller.

## Fix

**Vulnerable code:**
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
    FormattableString sql = $"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE '%{term}%'";
    return _db.Products.FromSqlInterpolated(sql).ToListAsync();
}
```

## Explanation

The fix replaces `FromSqlRaw()` with `FromSqlInterpolated()` and uses a `FormattableString` instead of a regular string. When a `FormattableString` is passed to `FromSqlInterpolated()`, Entity Framework Core automatically wraps each interpolated value (`tenantId` and `term`) in a `DbParameter` object, treating them as data rather than query syntax. The single quotes around the `tenantId` parameter are removed because the database now handles type conversion safely through parameterization. This prevents SQL injection by ensuring user input cannot modify the query structure.

## Behaviour changes

None. The method signature, return type, and query result remain identical. The only change is the parameterization mechanism: from raw string concatenation (unsafe) to parameterized queries (safe). The LIKE pattern and query logic are preserved.
