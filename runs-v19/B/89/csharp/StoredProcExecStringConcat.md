## Verdict

Exploitable. The `customerId` parameter (untrusted input from the caller) is embedded directly into the SQL string via string interpolation on line 7, then executed at line 10 via `ExecuteReader()`. An attacker can pass malicious SQL syntax (e.g., `' OR '1'='1`) to manipulate the stored procedure call.

## Source

**Method parameter:** `customerId` in the `GetOrdersByCustomer()` method signature (line 5) is the untrusted data source. It flows through string interpolation into the `SqlCommand` constructor and is executed without parameterization.

**Call chain:**
- Line 7: `$"EXEC dbo.GetOrdersByCustomer '{customerId}'"` - string concatenation introduces the vulnerability
- Line 10: `command.ExecuteReader()` - SQL execution sink

## Fix

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
        command.Parameters.Add("@CustomerId", SqlDbType.NVarChar).Value = customerId;

        return command.ExecuteReader();
    }
}
```

## Explanation

The fix eliminates the injection by replacing string concatenation with parameterized query execution. The `customerId` is no longer embedded in the SQL string; instead, it is passed as a separate `SqlParameter` with an explicit type (`SqlDbType.NVarChar`). 

The command is now invoked as a stored procedure (CommandType.StoredProcedure) with parameters, which is the proper and safe pattern for calling SQL Server stored procedures with untrusted input. The database driver automatically handles escaping and treats the parameter value as data, not executable SQL. This prevents an attacker from injecting SQL syntax.

The `using System.Data;` directive was added to make the `CommandType` and `SqlDbType` enums available.

## Behaviour changes

1. **CommandType change:** The original code left CommandType at its default value (Text), which interprets the entire string as an SQL command. The fix explicitly sets CommandType to StoredProcedure, which is the correct approach for calling stored procedures. This is not a regression—it is the proper way to invoke parameterized stored procedures and aligns with the stored procedure invocation pattern.

2. **Parameter passing:** Parameters are now passed by name (@CustomerId) instead of being embedded in the SQL string. This requires that the stored procedure `dbo.GetOrdersByCustomer` has a parameter that accepts the CustomerId value. The parameter binding by name is standard practice and compatible with SQL Server stored procedures.

3. **SQL string simplification:** The SQL string is now static (`"dbo.GetOrdersByCustomer"`) rather than dynamically constructed. This eliminates the injection vector entirely and improves query plan caching at the database server.

The fix preserves the original contract: it returns a `SqlDataReader` containing the stored procedure's result set, maintains the same exception behavior on database errors, and does not alter the method's signature or calling interface.
