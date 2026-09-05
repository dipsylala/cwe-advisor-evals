## Verdict

Exploitable. The `tenantId` and `term` parameters originate from user input (query parameter `q` in ProductSearchController) and flow directly into a SQL query via string interpolation, without parameterization. The sink `FromSqlRaw()` executes the concatenated SQL, allowing an attacker to inject arbitrary SQL logic.

## Source

**Source:** `term` parameter arrives as an untrusted query parameter (`q`) from ProductSearchController line 20. `tenantId` comes from the user's security claim, also untrusted at the point of SQL construction.

**Sink:** Line 17 in ProductSearchRepository.cs: `_db.Products.FromSqlRaw(sql).ToListAsync()` executes SQL built by concatenating user input directly into the query string on line 16.

**Data Flow:**
1. ProductSearchController receives `q` as a query parameter
2. Passes it to ProductSearchRepository.SearchAsync() as `term`
3. Line 16 builds SQL by string interpolation: `$"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'"`
4. Line 17 executes with FromSqlRaw(), which does not parameterize the interpolated values

## Fix

**Vulnerable code (line 16-17):**
```csharp
var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'";
return _db.Products.FromSqlRaw(sql).ToListAsync();
```

**Fixed code:**
```csharp
var searchPattern = $"%{term}%";
var sql = $"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {searchPattern}";
return _db.Products.FromSqlInterpolated(sql).ToListAsync();
```

## Explanation

The fix replaces `FromSqlRaw()` with `FromSqlInterpolated()`, which automatically wraps each interpolated value in a `DbParameter` instead of concatenating it into the SQL string. In the fixed code, the interpolated expressions `{tenantId}` and `{searchPattern}` are converted to SQL parameters with proper escaping, preventing SQL injection. The `searchPattern` variable formats the wildcard pattern (`%{term}%`) as a complete parameter value rather than embedding the raw term into the SQL syntax. This ensures that input like `' OR '1'='1` is treated as a literal string value for the LIKE comparison, not as executable SQL logic.

## Behaviour changes

None. `FromSqlInterpolated()` uses the same execution semantics as `FromSqlRaw()` for the parameterized values. It returns the same `IQueryable<Product>` that is converted to `List<Product>` by `ToListAsync()`. The LIKE pattern logic is preserved—wildcards are still applied, and the matching behavior remains identical for legitimate input. The only difference is that user-supplied data is now safely isolated from the SQL query structure.
