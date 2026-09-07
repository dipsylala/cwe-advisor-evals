## Verdict

SQL Injection vulnerability via string concatenation in stored procedure call.

## Source

The `customerId` parameter from the method signature is untrusted external input.

## Fix

### File: CustomerOrdersRepository.cs

```csharp
using System.Data;
using System.Data.SqlClient;

public class CustomerOrdersRepository
{
    public SqlDataReader GetOrdersByCustomer(SqlConnection connection, string customerId)
    {
        var command = new SqlCommand("dbo.GetOrdersByCustomer", connection)
        {
            CommandType = CommandType.StoredProcedure
        };
        
        command.Parameters.Add("@CustomerId", SqlDbType.NVarChar).Value = customerId;
        
        return command.ExecuteReader();
    }
}
```

## Explanation

The original code concatenated the `customerId` directly into the SQL command string via string interpolation (`$"EXEC dbo.GetOrdersByCustomer '{customerId}'"`). This allows an attacker to inject SQL syntax by controlling the `customerId` value.

The fix uses parameterized stored procedure execution:
1. Set `CommandType` to `StoredProcedure` instead of relying on a command string
2. Pass `customerId` as a separate parameter via `Parameters.Add()` with an explicit `SqlDbType` (NVarChar is appropriate for string data)
3. Assign the untrusted value only to the parameter's `Value` property

This ensures the database driver treats `customerId` as data, not as SQL structure. The stored procedure receives it as a typed input parameter, completely preventing injection.

## Behaviour changes

The application still calls the `dbo.GetOrdersByCustomer` stored procedure and returns the same `SqlDataReader` with identical query results. The only difference is that the parameter is now passed securely through the parameterization mechanism rather than embedded in the command text.
