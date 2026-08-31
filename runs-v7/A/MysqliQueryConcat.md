## Verdict

SQL injection vulnerability confirmed. The application concatenates unsanitized user input directly into an SQL query string and passes it to `mysqli_query()`, allowing an attacker to inject arbitrary SQL commands.

## Source

Line 5 builds the query:
```php
$query = "SELECT id, username, email FROM users WHERE username = '" . $username . "'";
```

The `$username` parameter comes from `$_GET['username']` (line 19), which is user-controlled and unparsed. The function receives it as a string parameter (line 3) and interpolates it directly into the SQL query without escaping or parameterization.

Line 8 executes the unsanitized query:
```php
$result = mysqli_query($db, $query);
```

## Fix

Replace the concatenated query with a prepared statement. The function should be rewritten as:

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

Alternatively, using the procedural mysqli API:

```php
$stmt = mysqli_prepare($db, "SELECT id, username, email FROM users WHERE username = ?");
mysqli_stmt_bind_param($stmt, "s", $username);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
```

The placeholder `?` separates the SQL structure from the user-supplied data. The `bind_param("s", $username)` call specifies that `$username` is a string (`s`) and instructs mysqli to safely encode it according to SQL string rules, preventing injection.

## Explanation

Prepared statements are the primary defense against SQL injection. They enforce a structural separation between the SQL command template and the data supplied by the user, ensuring that user input cannot alter the query's meaning or inject new SQL commands. Parameterized queries are the standard defense in every mainstream database API, including mysqli, PDO, and others.

The placeholder marks the location where data goes; the data itself is encoded separately, never parsed as SQL syntax. This prevents attackers from closing string quotes, modifying operators, or injecting `UNION`, `DROP`, or other commands.

The original code's concatenation approach is vulnerable to inputs like `' OR '1'='1`, which would rewrite the query logic, or `'; DROP TABLE users; --`, which would execute additional commands.
