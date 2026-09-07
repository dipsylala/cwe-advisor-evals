## Verdict
Confirmed CWE-89 (SQL Injection). String interpolation directly embeds an unsanitized parameter into the SQL command, allowing SQL metacharacters to break out of the quoted value and execute arbitrary commands.

## Source
Line 7 of `CustomerOrdersRepository.cs` uses string interpolation in a SqlCommand:
```
var command = new SqlCommand($"EXEC dbo.GetOrdersByCustomer '{customerId}'", connection);
```

The `customerId` parameter flows untrusted into the SQL string without escaping. An attacker can inject SQL by supplying a value like `' OR '1'='1` or `'; DROP TABLE Orders; --`.

## Fix

### File: CustomerOrdersRepository.cs
```csharp
using System;
using System.Data;
using System.Data.SqlClient;

public class CustomerOrdersRepository
{
    public SqlDataReader GetOrdersByCustomer(SqlConnection connection, string customerId)
    {
        var command = new SqlCommand("dbo.GetOrdersByCustomer", connection);
        command.CommandType = CommandType.StoredProcedure;
        command.Parameters.AddWithValue("@customerId", customerId ?? "");

        return command.ExecuteReader();
    }
}
```

## Explanation
The fix replaces string interpolation with parameterized queries. Instead of embedding `customerId` into the SQL string, the code now:

1. Sets `CommandType` to `StoredProcedure` to indicate a direct call to the stored procedure by name (not an arbitrary SQL string).
2. Adds `customerId` as a typed parameter using `Parameters.AddWithValue()`, which SQL Server treats as a value (never as SQL syntax), regardless of its contents.
3. Adds a null-coalescing operator (`?? ""`) to handle null inputs safely.

This approach separates the SQL command structure from the data, preventing SQL injection. The stored procedure name and parameter name are controlled by the application code; only the value flows from the caller.
