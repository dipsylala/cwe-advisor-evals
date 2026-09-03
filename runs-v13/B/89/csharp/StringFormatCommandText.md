## Verdict

exploitable

## Source

**CWE-89 (SQL Injection)** in WidgetAdminController.cs

**Source:** The `ownerName` route parameter (line 21) originates from an HTTP DELETE request and is attacker-controlled via the URL path `admin/widgets/by-owner/{ownerName}`.

**Data Flow:** `ownerName` → string.Format() interpolation (line 30) → SqlCommand.CommandText → ExecuteNonQuery() sink (line 33)

**Sink:** `SqlCommand.ExecuteNonQuery()` executes the SQL query on line 33. The command text is built by concatenating untrusted input via `string.Format("DELETE FROM widgets WHERE owner = '{0}'", ownerName)` on line 30.

## Fix

**Vulnerable Code:**
```csharp
command.CommandText = string.Format("DELETE FROM widgets WHERE owner = '{0}'", ownerName);
rowsDeleted = command.ExecuteNonQuery();
```

**Fixed Code:**
```csharp
command.CommandText = "DELETE FROM widgets WHERE owner = @ownerName";
command.Parameters.Add("@ownerName", SqlDbType.NVarChar).Value = ownerName;
rowsDeleted = command.ExecuteNonQuery();
```

## Explanation

Replace the string concatenation with a parameterized query using `SqlCommand.Parameters`. The fixed code treats `ownerName` as data (via the `@ownerName` parameter) rather than as executable SQL code. The `Parameters.Add()` method with explicit `SqlDbType.NVarChar` ensures type safety and prevents SQL injection. When parameterized, special characters like single quotes in the value are escaped automatically by the SQL Server driver, preventing attackers from breaking out of the string context or injecting additional SQL commands. The sink contract is preserved: `ExecuteNonQuery()` still returns the row count, throws on SQL errors, and requires no other changes to error handling.

## Behaviour changes

none
