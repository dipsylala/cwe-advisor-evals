## Verdict

Confirmed. `customerId` is concatenated directly into a T-SQL string that is executed via `SqlCommand.ExecuteReader()`, letting an attacker close the quoted literal and inject arbitrary SQL or additional statements into the `EXEC` call.

## Source

`customerId` — the `string` parameter of `CustomerOrdersRepository.GetOrdersByCustomer(SqlConnection connection, string customerId)` — is attacker-controlled input flowing straight from the method signature into the command text with no validation or encoding.

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
        command.Parameters.Add("@CustomerId", SqlDbType.NVarChar, 50).Value = customerId;

        return command.ExecuteReader();
    }
}
```

## Explanation

The original code built the command as a literal T-SQL string (`$"EXEC dbo.GetOrdersByCustomer '{customerId}'"`), so any single quote in `customerId` breaks out of the string literal and lets the caller append arbitrary SQL that runs with the connection's privileges (e.g. `x'; DROP TABLE Orders--`).

The fix calls the stored procedure through `SqlCommand.CommandType = CommandType.StoredProcedure` and passes `customerId` as a `SqlParameter` (`@CustomerId`) instead of splicing it into the command text. ADO.NET sends the parameter value to SQL Server separately from the procedure call, so the driver never re-parses it as part of the statement — the value can only ever be interpreted as data for the parameter, regardless of its content (quotes, semicolons, comment sequences, etc.). This preserves the original behavior (same stored procedure, same logical argument) while eliminating the injection point; no other code changes are needed since the call still returns a `SqlDataReader` from `ExecuteReader()`.
