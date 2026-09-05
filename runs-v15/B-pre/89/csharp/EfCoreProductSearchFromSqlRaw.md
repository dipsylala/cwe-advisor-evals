## Verdict

Exploitable. The code directly interpolates user input into a SQL query via `FromSqlRaw()` without parameterization, allowing an attacker to inject arbitrary SQL.

## Source

User-supplied search parameter passed to the repository method (e.g., from a query string, form input, or route parameter).

## Fix

Replace `FromSqlRaw()` with `FromSqlInterpolated()` (EF Core 6.0+) or `FromSql()` (EF Core 7.0+), which automatically parameterize interpolated values.

**Vulnerable code (FromSqlRaw with string interpolation):**
```csharp
var results = context.Products.FromSqlRaw($"SELECT * FROM Products WHERE ProductName = '{searchTerm}'").ToList();
```

**Fixed code (using FromSqlInterpolated):**
```csharp
var results = context.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE ProductName = {searchTerm}").ToList();
```

Alternatively for EF Core 7.0+:
```csharp
var results = context.Products.FromSql($"SELECT * FROM Products WHERE ProductName = {searchTerm}").ToList();
```

## Explanation

`FromSqlInterpolated` (or `FromSql` in EF Core 7.0+) treats interpolated values as `DbParameter` objects rather than concatenating them directly into the SQL string. This ensures user input is always treated as data, not executable SQL code. The parameterized approach prevents attackers from manipulating query logic by injecting SQL syntax such as `' OR '1'='1`. The application behavior remains unchanged; only the internal mechanism of binding data to the query differs.

## Behaviour changes

- **Parameter handling**: Values are now passed as database parameters rather than string-interpolated into the query. This is the intended security fix.
- **No functional change**: Result set and query semantics remain identical.
- **Performance**: Slight performance improvement because parameterized queries are cached and reused by the database engine.
- **Sink contract preserved**: The method continues to return an `IQueryable<T>` or `List<T>` as before; no change to return type or chaining behavior.
