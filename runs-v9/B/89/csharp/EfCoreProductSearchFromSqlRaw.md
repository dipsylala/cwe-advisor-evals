# CWE-89: SQL Injection - ProductSearchRepository.SearchAsync

## Verdict

exploitable (confidence: high)

`ProductSearchController.Search` passes the unauthenticated-length-unchecked query-string parameter `q` straight into `ProductSearchRepository.SearchAsync(tenantId, q ?? "")` as `term`, alongside `tenantId` taken from the caller's `tenant_id` JWT claim. Neither value is validated or escaped before reaching the sink. `FromSqlRaw` is not inherently unsafe (EF Core documents it as safe when values are supplied as `DbParameter`/interpolation-hole arguments), but here the query text itself is built by string interpolation into a plain `string` before being handed to `FromSqlRaw`, so both values become literal SQL text - the classic case the taint sink is meant to catch.

Assumption: the target EF Core version could not be determined from the two files in the call chain (no project file was in scope), so the fix uses `FromSqlInterpolated`, which is available on all EF Core versions that expose `FromSqlRaw`, rather than `FromSql` (the EF Core 7.0+ spelling) - a narrower, version-safe choice.

## Source

- Source: HTTP query parameter `q` in `ProductSearchController.Search([FromQuery] string q)` (line 17 of `ProductSearchController.cs`), and the `tenant_id` claim read at line 19. Both flow unchanged into `_repository.SearchAsync(tenantId, q ?? "")` at line 20.
- Sink: `ProductSearchRepository.cs` line 16-17 - `var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'"; return _db.Products.FromSqlRaw(sql).ToListAsync();`. `tenantId` and `term` are interpolated directly into the SQL text with no parameters passed to `FromSqlRaw`, so an attacker-controlled `q` such as `x' OR '1'='1` or a stacked/UNION payload alters query structure and can read rows across tenants.

Sink contract (`FromSqlRaw(sql).ToListAsync()`): returns `Task<List<Product>>` materialized by EF Core's async query pipeline; discards nothing beyond the normal result set; the `params object[] parameters` argument is left implicit (empty) even though two untrusted values are embedded in `sql` - that omission is the vulnerability, not merely the choice of `FromSqlRaw`; on failure it throws the same `DbException`/EF exceptions callers already handle upstream (none is currently caught locally, so this stays unchanged).

## Fix

No library or version change is required - `Microsoft.EntityFrameworkCore` already provides the safe API used below.

Vulnerable code (`ProductSearchRepository.cs`, lines 14-18):

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.List<Product>> SearchAsync(string tenantId, string term)
{
    var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'"; // tenantId/term concatenated into SQL text
    return _db.Products.FromSqlRaw(sql).ToListAsync();
}
```

Fixed code:

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.List<Product>> SearchAsync(string tenantId, string term)
{
    var likePattern = $"%{term}%";
    return _db.Products
        .FromSqlInterpolated($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {likePattern}")
        .ToListAsync();
}
```

## Explanation

The fix removes the intermediate `string sql = $"..."` assignment and instead passes the interpolated string literal directly as the argument to `FromSqlInterpolated`. That distinction is what fixes the bug: when an interpolated string literal is assigned to a `string`-typed variable, the compiler renders it to plain text immediately, which is exactly how `tenantId` and `term` became literal SQL. When the same literal is passed directly to a `FormattableString` parameter (as `FromSqlInterpolated` declares), the compiler instead captures each `{ }` hole separately, and EF Core converts every hole to a `DbParameter` bound by type and value rather than by text substitution - so a value like `x' OR '1'='1` is sent to the database as data and cannot change the query's structure. The `%...%` wildcard concatenation for the `LIKE` pattern is done in C# on a local variable before it goes into the hole, so it only builds the parameter's value, not the SQL text, and stays safe under the same mechanism.

## Behaviour changes

None beyond closing the weakness. Return type, materialization via `ToListAsync()`, the `TenantId =` and `Name LIKE '%...%'` matching semantics, and unhandled-exception behavior on query failure are all unchanged; the only difference is that `tenantId` and `term` now reach the database as bound parameters instead of interpolated text.
