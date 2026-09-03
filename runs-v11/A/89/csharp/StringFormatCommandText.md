## Verdict
Confirmed SQL injection vulnerability via unsafe string interpolation into SQL command text.

## Source
Line 30 constructs the SQL query using `string.Format()` with user-supplied input from the `ownerName` route parameter:
```csharp
command.CommandText = string.Format("DELETE FROM widgets WHERE owner = '{0}'", ownerName);
```

The parameter flows directly into the SQL command text without any escaping or parameterization, creating a taint flow from the HTTP route parameter to the SQL sink at line 33's `ExecuteNonQuery()`.

## Fix
Replace string interpolation with a parameterized query. Use `SqlCommand.Parameters` to separate the SQL structure from user-supplied values:

```csharp
command.CommandText = "DELETE FROM widgets WHERE owner = @ownerName";
command.Parameters.AddWithValue("@ownerName", ownerName);
rowsDeleted = command.ExecuteNonQuery();
```

## Explanation
Parameterized queries (prepared statements) are the primary defence against SQL injection. They ensure that the database engine distinguishes between SQL syntax and data by sending the structure and parameters separately. The `@ownerName` parameter placeholder in the query string is filled by the database driver using the value from `Parameters.AddWithValue()`, guaranteeing that even if `ownerName` contains SQL metacharacters like single quotes or `--` comments, they are treated as literal string data, not as SQL syntax.

This approach eliminates the attack surface: a malicious input like `' OR '1'='1` will be treated as the literal owner name to match, not as part of the SQL structure.
