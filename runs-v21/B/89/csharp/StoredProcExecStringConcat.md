## Verdict

The finding is valid. Line 7 constructs a SQL command by string interpolation, concatenating the untrusted `customerId` parameter directly into the command text before passing it to `ExecuteReader()` at line 10. An attacker can inject SQL by controlling the `customerId` value.

## Source

`customerId` parameter received by `GetOrdersByCustomer()` at line 5.

## Fix

Replace string concatenation with parameterized stored procedure invocation. Pass `customerId` as a bound parameter using `SqlCommand.Parameters.Add()` with an explicit `SqlDbType`.

### File: CustomerOrdersRepository.cs

```csharp
using System.Data;
using System.Data.SqlClient;

public class CustomerOrdersRepository
{
    public SqlDataReader GetOrdersByCustomer(SqlConnection connection, string customerId)
    {
        var command = new SqlCommand("dbo.GetOrdersByCustomer", connection);
        command.CommandType = CommandType.StoredProcedure;
        command.Parameters.Add("@customerId", SqlDbType.NVarChar).Value = customerId;

        return command.ExecuteReader();
    }
}
```

## Explanation

The original code embedded `customerId` directly into the SQL string using string interpolation, which is vulnerable to injection attacks. The fix:

1. **Use stored procedure invocation instead of dynamic SQL:** Set `CommandType` to `StoredProcedure` and pass the procedure name directly to `SqlCommand`.
2. **Parameterize the input:** Use `Parameters.Add()` with an explicit `SqlDbType.NVarChar` type, making the customerId a bound parameter rather than part of the query string.
3. **Assign the value to the parameter:** The parameter is bound to the actual value via the `.Value` property.

This approach ensures `customerId` is treated as data, not as executable SQL, preventing injection attacks. The database engine receives the parameter value separately from the query structure.

## Behaviour changes

- **Before:** Accepts arbitrary SQL code in the `customerId` parameter, allowing injection.
- **After:** `customerId` is safely passed as a parameter value; any special characters are treated as literal data.
- **API change:** `SqlCommand` now uses `CommandType.StoredProcedure` to invoke the stored procedure by name rather than building an EXEC statement string.
- **No functional change to the application:** The stored procedure is invoked identically from the database perspective; only the transmission mechanism is hardened.
