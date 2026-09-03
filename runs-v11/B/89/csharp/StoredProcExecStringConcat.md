## Verdict

SQL Injection vulnerability confirmed. The code concatenates user input (`customerId`) directly into a SQL command string using string interpolation, allowing attackers to inject SQL logic.

## Source

**File:** `CustomerOrdersRepository.cs`, line 7-10

**Vulnerable code:**
```csharp
var command = new SqlCommand($"EXEC dbo.GetOrdersByCustomer '{customerId}'", connection);
return command.ExecuteReader();
```

**Data flow:** The `customerId` parameter (untrusted) flows directly into the SQL command string via string interpolation (`$"...{customerId}..."`), then to `ExecuteReader()` which executes the malicious query.

**Attack scenario:** An attacker supplies `customerId = "' OR '1'='1' --"`, producing the query:
```sql
EXEC dbo.GetOrdersByCustomer '' OR '1'='1' --'
```
This bypasses the intended procedure call and returns all customer orders regardless of ID.

## Fix

Replace string concatenation with parameterized stored procedure execution:

```csharp
public SqlDataReader GetOrdersByCustomer(SqlConnection connection, string customerId)
{
    var command = new SqlCommand("dbo.GetOrdersByCustomer", connection);
    command.CommandType = CommandType.StoredProcedure;
    command.Parameters.Add("@customerId", SqlDbType.VarChar, 50).Value = customerId;
    
    return command.ExecuteReader();
}
```

**Key changes:**
1. Set the command text to the stored procedure name only (`"dbo.GetOrdersByCustomer"`)
2. Set `CommandType` to `CommandType.StoredProcedure` to indicate it is a procedure, not raw SQL
3. Add the `customerId` as a parameter using `Parameters.Add()` with explicit `SqlDbType.VarChar`
4. Assign the user input to the parameter's `Value` property after creation, ensuring it is treated as data, not query structure

The `VarChar` type with size 50 assumes the customer ID is a string of up to 50 characters; adjust the size to match your actual schema.

## Explanation

The vulnerability stems from string interpolation mixing SQL structure with untrusted data. The original code uses `$"EXEC dbo.GetOrdersByCustomer '{customerId}'"`, which constructs the entire command as a string before execution.

The remediation uses parameterized queries, which separate query structure from data:
- The command text is now the procedure name alone (structure)
- The `customerId` is added as a `SqlParameter` (data)
- SQL Server receives the procedure call and parameter value separately, treating the parameter value as data only

This prevents the attacker from injecting SQL keywords or syntax, because the database engine never parses the parameter value as SQL.

**Why this approach:**
- The guidance identifies parameterized queries as the primary defence against SQL injection
- For stored procedures in C#, `SqlCommand.Parameters.Add()` with explicit type is preferred over string concatenation
- Using `CommandType.StoredProcedure` tells the provider to call the procedure, not parse the text as SQL, adding a second layer of protection
- The type specification (`SqlDbType.VarChar`) ensures the value is coerced to the expected type before transmission to SQL Server

## Behaviour changes

**Before:**
- User input is embedded directly in the SQL command string
- The database receives a single string that the SQL engine must parse to extract procedure call vs. injected logic
- Malicious input with quotes, semicolons, or SQL keywords succeeds in rewriting the query

**After:**
- User input is passed as a separate parameter
- The database receives the procedure name and parameters as distinct values
- The parameter value is never parsed as SQL, regardless of its content
- The method signature and return type remain unchanged; callers see no API difference
- Performance is identical or improved, as the database can cache the procedure plan separately from parameter values
