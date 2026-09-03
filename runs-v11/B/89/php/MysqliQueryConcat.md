## Verdict

VULNERABLE. The code constructs an SQL query by concatenating user input directly into the query string without parameterization, enabling SQL injection attacks.

## Source

Line 5: `$query = "SELECT id, username, email FROM users WHERE username = '" . $username . "'";`

The `$username` parameter (derived from untrusted user input at line 19: `$_GET['username']`) is concatenated directly into the SQL query string. This concatenated query is then passed to the taint sink `mysqli_query()` at line 8.

## Fix

Replace string concatenation with a prepared statement using MySQLi's parameterized query API. Convert the concatenated query to use a placeholder and bind the parameter separately:

```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $stmt = $db->prepare("SELECT id, username, email FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result === false) {
        return null;
    }

    return $result->fetch_assoc() ?: null;
}
```

The key changes:
1. Use `mysqli::prepare()` with a placeholder `?` instead of concatenating the value into the query string
2. Bind the `$username` parameter using `bind_param("s", $username)` where `"s"` indicates a string type
3. Call `execute()` to run the prepared statement with the bound parameters
4. Retrieve results using `get_result()` instead of directly using the mysqli_query result

## Explanation

The vulnerability occurs because concatenating untrusted user input directly into an SQL query allows attackers to inject arbitrary SQL commands. For example, an attacker providing `' OR '1'='1` as the username would transform the query into:

```sql
SELECT id, username, email FROM users WHERE username = '' OR '1'='1'
```

This would return all users instead of searching for a specific username.

Prepared statements fix this by separating the query structure from the data. The `?` placeholder marks where a parameter goes, and the database driver ensures that the bound value is always treated as data, never as executable SQL code. Even if an attacker provides `' OR '1'='1`, it will be treated as a literal string value to search for, not as SQL syntax.

The type specifier `"s"` in `bind_param()` indicates that the parameter is a string, and MySQLi applies appropriate escaping at the driver level based on the connection's character set.

## Behaviour changes

- User-supplied usernames that previously could contain SQL metacharacters (single quotes, semicolons, SQL keywords) are now treated as literal string values to search for
- The query now executes only the intended SELECT logic; injected SQL commands in the username parameter are ignored
- Query performance may improve slightly as the prepared statement is compiled once and executed multiple times, though this effect is typically negligible for single executions
- Error handling remains unchanged; the function still returns null if the query fails
