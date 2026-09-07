## Verdict

True Positive. The code constructs a stored procedure call using string interpolation, allowing attacker-controlled input to break out of the quoted argument and inject arbitrary SQL commands.

## Source

Line 7 builds the command text using string interpolation:

```csharp
var command = new SqlCommand($"EXEC dbo.GetOrdersByCustomer '{customerId}'", connection);
```

The `customerId` parameter is directly embedded into the SQL string with no escaping or parameterization. An attacker providing input like `' UNION SELECT * FROM Users; --` can alter query logic and access unauthorized data.

## Fix

Use parameterized stored procedure execution. Set `CommandType` to `StoredProcedure` and add parameters via `SqlParameter`:

```csharp
using System.Data.SqlClient;

public class CustomerOrdersRepository
{
    public SqlDataReader GetOrdersByCustomer(SqlConnection connection, string customerId)
    {
        var command = new SqlCommand("dbo.GetOrdersByCustomer", connection)
        {
            CommandType = System.Data.CommandType.StoredProcedure
        };
        
        command.Parameters.AddWithValue("@customerId", customerId);
        
        return command.ExecuteReader();
    }
}
```

## Explanation

When `CommandType.StoredProcedure` is used, the command name is passed separately from arguments. SqlParameter binds values at the database protocol level as typed data, not as part of the command text. The stored procedure receives the parameter value without any opportunity for string-based injection.

This approach:
- Eliminates string concatenation in SQL entirely
- Leverages SQL Server's stored procedure calling convention
- Ensures the parameter type and value are validated by the database driver
- Prevents injection even if the input contains quotes, semicolons, or other SQL syntax characters
