## Verdict
SQL injection via unparameterized string interpolation in stored procedure execution.

## Source
Line 7 of `CustomerOrdersRepository.cs` uses string interpolation to embed the `customerId` parameter directly into the SQL command:
```csharp
var command = new SqlCommand($"EXEC dbo.GetOrdersByCustomer '{customerId}'", connection);
```

An attacker controlling `customerId` can inject SQL commands. For example, passing `' OR '1'='1` would result in `EXEC dbo.GetOrdersByCustomer '' OR '1'='1'`, altering query logic.

## Fix
Replace string interpolation with parameterized queries using `SqlParameter`:

```csharp
var command = new SqlCommand("EXEC dbo.GetOrdersByCustomer @CustomerId", connection);
command.Parameters.AddWithValue("@CustomerId", customerId);
return command.ExecuteReader();
```

Alternatively, use explicit `SqlParameter` with type specification:

```csharp
var command = new SqlCommand("EXEC dbo.GetOrdersByCustomer @CustomerId", connection);
command.Parameters.Add("@CustomerId", SqlDbType.VarChar).Value = customerId;
return command.ExecuteReader();
```

## Explanation
Parameterized queries separate SQL structure from data. The database engine treats parameter values as data only, never as executable SQL code, regardless of their content. String interpolation has no such separation—the interpolated value becomes part of the SQL command text itself, allowing metacharacters to alter query logic.

`SqlCommand` and `SqlParameter` are part of `System.Data.SqlClient` and represent the standard SQL Server defense against injection in C#. The parameter name (prefixed with `@`) corresponds to the placeholder in the command string; the actual value is bound separately and safely by the database driver.
