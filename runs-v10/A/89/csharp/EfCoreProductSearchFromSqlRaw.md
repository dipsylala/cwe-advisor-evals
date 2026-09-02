## Verdict
Confirmed. SQL injection via unparameterized string interpolation in `FromSqlRaw()`.

## Source
Line 16 constructs a SQL string by directly embedding `tenantId` and `term` parameters into the query:
```csharp
var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'";
return _db.Products.FromSqlRaw(sql).ToListAsync();
```

An attacker-controlled `term` or `tenantId` can close the string delimiter and inject arbitrary SQL.

## Fix
Replace `FromSqlRaw()` with `FromSqlInterpolated()`, which automatically converts interpolated parameters into SQL parameters:
```csharp
return _db.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {$"%{term}%"}").ToListAsync();
```

Remove the manual single quotes around the placeholders; `FromSqlInterpolated` handles parameterization. Note: LIKE patterns still require manual concatenation in the parameter value itself, so `$"%{term}%"` constructs the pattern string before being passed as a parameter.

## Explanation
`FromSqlRaw()` executes the string exactly as written—the values are embedded textually, not as parameters. `FromSqlInterpolated()` inspects the interpolated string expression and converts each `{placeholder}` into a database parameter, preventing SQL injection. The SQL statement is parameterized at the database driver level, ensuring user input cannot break out of its intended data context.
