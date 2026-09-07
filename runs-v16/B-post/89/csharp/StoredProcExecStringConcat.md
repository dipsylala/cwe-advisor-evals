## Verdict

Valid finding. CWE-89 (SQL Injection) confirmed. The `customerId` parameter is unsanitized and directly embedded into the SQL command via string interpolation, allowing an attacker to inject arbitrary SQL code by escaping the single quotes.

## Source

```csharp
var command = new SqlCommand($"EXEC dbo.GetOrdersByCustomer '{customerId}'", connection);
return command.ExecuteReader();
```

The `customerId` parameter is concatenated into the SQL command string. An attacker can pass a value like `'; DROP TABLE Orders; --` to execute arbitrary SQL.

## Fix

```csharp
var command = new SqlCommand("dbo.GetOrdersByCustomer", connection)
{
    CommandType = CommandType.StoredProcedure
};
command.Parameters.Add("@customerId", SqlDbType.NVarChar).Value = customerId;
return command.ExecuteReader();
```

## Explanation

The fixed code uses a parameterized approach to call the stored procedure safely. Instead of concatenating the `customerId` into a SQL string, the code:

1. Creates a `SqlCommand` with the stored procedure name only
2. Sets `CommandType` to `CommandType.StoredProcedure` to indicate it's a stored procedure call
3. Uses `Parameters.Add()` with an explicit `SqlDbType` to bind the `customerId` as a parameter
4. The database driver treats the parameter value as data, never as executable SQL code

This ensures the input cannot escape the parameter context and inject SQL commands.

## Behaviour changes

No functional behaviour changes. The stored procedure `dbo.GetOrdersByCustomer` receives the `customerId` value as a parameter rather than as part of the query text, but the result set returned to the caller is identical. The `ExecuteReader()` method signature and return type remain unchanged.
