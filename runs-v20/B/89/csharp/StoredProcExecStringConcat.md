## Verdict

exploitable

- **cwe_id**: CWE-89
- **location**: `CustomerOrdersRepository.cs`, line 10 (sink); line 7 (query construction)
- **confidence**: high

## Source

`customerId`, the `string` parameter passed into the public method `GetOrdersByCustomer(SqlConnection connection, string customerId)`. The repository has no caller in this file, so the value's ultimate origin (request parameter, route value, etc.) isn't visible here, but as a public repository method taking a bare `string` with no validation, it must be treated as untrusted at this boundary.

## Fix

### File: CustomerOrdersRepository.cs

```csharp
using System.Data;
using System.Data.SqlClient;

public class CustomerOrdersRepository
{
    public SqlDataReader GetOrdersByCustomer(SqlConnection connection, string customerId)
    {
        var command = new SqlCommand("EXEC dbo.GetOrdersByCustomer @CustomerId", connection);
        command.Parameters.Add("@CustomerId", SqlDbType.NVarChar).Value = customerId;

        return command.ExecuteReader();
    }
}
```

## Explanation

The original code built the `EXEC` statement with string interpolation, splicing `customerId` directly into the SQL text (`$"EXEC dbo.GetOrdersByCustomer '{customerId}'"`). A value such as `x'; DROP TABLE Orders--` closes the literal and injects arbitrary statements that execute with the connection's privileges. The fix keeps the same `EXEC` invocation as a parameterized command: the literal is replaced with the placeholder `@CustomerId`, and the actual value is bound through `SqlCommand.Parameters.Add("@CustomerId", SqlDbType.NVarChar).Value = customerId`. ADO.NET sends the command text and the parameter value to SQL Server separately (via `sp_executesql` under the hood), so `customerId` is always treated as a single data value passed positionally into the stored procedure call, never as SQL syntax - the injection is closed regardless of what characters the value contains. The placeholder name `@CustomerId` only has to match between the command text and the `Parameters.Add` call; because it is consumed positionally by the `EXEC` statement, it does not need to match whatever parameter name `dbo.GetOrdersByCustomer` actually declares, so no assumption about the stored procedure's own signature is required. No size is passed for the `NVarChar` type, so ADO.NET sizes the parameter from the runtime length of `customerId` rather than a guessed column width, avoiding any truncation risk from an incorrect assumed size.

## Behaviour changes

- Added `using System.Data;` - required for the `SqlDbType` enum, which lives in `System.Data` rather than `System.Data.SqlClient`. Reason: needed to declare the parameter's type; does not change runtime behaviour.
- `CommandType` remains at its default (`CommandType.Text`), matching the original command - not changed.
- Return value (`SqlDataReader` from `ExecuteReader()`), the connection argument, method signature, and exception/failure behaviour are all unchanged.
- No new value is surfaced or discarded compared to the original; the only substantive change is that `customerId` is now bound as a parameter instead of being concatenated into the command text, which is the injection fix itself.

**Verification**: No C# compiler (`csc`/`dotnet`) was reachable in this environment, so the fix was checked by manual read-through instead: `System.Data.SqlClient.SqlCommand`, `SqlCommand.Parameters.Add(string, SqlDbType)`, and `System.Data.SqlDbType.NVarChar` are all real, unchanged members of the .NET base class library already implied by the file's existing `using System.Data.SqlClient;` import; the only new import (`System.Data`) is the standard-library namespace that declares `SqlDbType`, per the loaded C# guidance. The method signature, parameter list, and return type are unchanged from the original, so no caller needs updating.

**Assumptions**: The stored procedure's actual declared parameter name is unknown (no procedure definition was in scope); the fix avoids depending on it by using positional parameter passing within the `EXEC` statement rather than named-parameter syntax (`@paramName = value`), so this does not affect correctness. Confidence remains high because this only affects the placeholder's internal naming, not the injection fix itself.
