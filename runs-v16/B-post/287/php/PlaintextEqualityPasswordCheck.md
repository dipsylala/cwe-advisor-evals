## Verdict

Exploitable. The code uses loose-equality comparison (`==`) on line 35 to verify a plaintext password against what is stored in the database, and does not employ constant-time verification or a hashing function. This is improper authentication (CWE-287).

## Source

User-supplied password from `$_POST['password']` (line 20), assigned to `$password` after type-casting to string. Attacker controls the plaintext value.

## Fix

**Vulnerable Code:**
```php
        // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
        if ($password == $user['password']) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];

            return ['success' => true, 'user_id' => $user['id']];
        }

        return ['success' => false, 'error' => 'Invalid username or password.'];
```

**Fixed Code:**
```php
        // Define a dummy hash for timing-safe verification on user-not-found path.
        // This constant should be defined at class level as:
        // private const DUMMY_HASH = '$2y$10$dummyhashforverificationpurposesonly123456789012';
        
        // On the user-found path, verify password against the stored hash.
        // On the user-not-found path, verify against DUMMY_HASH to equalize response time.
        if (password_verify($password, $user ? $user['password'] : self::DUMMY_HASH)) {
            if (!$user) {
                // User not found; timing-safe verification against dummy completed, but login denied.
                return ['success' => false, 'error' => 'Invalid username or password.'];
            }
            
            // Successful authentication: regenerate session and populate user context.
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];

            return ['success' => true, 'user_id' => $user['id']];
        }

        return ['success' => false, 'error' => 'Invalid username or password.'];
```

Alternatively, if the structure must be preserved more closely:

```php
        // Define constant at class level: private const DUMMY_HASH = '$2y$10$dummyhashforverificationpurposesonly123456789012';
        
        $passwordHash = $user['password'] ?? self::DUMMY_HASH;
        
        if (password_verify($password, $passwordHash)) {
            if (!$user) {
                return ['success' => false, 'error' => 'Invalid username or password.'];
            }
            
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];

            return ['success' => true, 'user_id' => $user['id']];
        }

        return ['success' => false, 'error' => 'Invalid username or password.'];
```

## Explanation

The vulnerability lies in using the loose-equality operator (`==`) to compare a plaintext password with a database value, which introduces two separate authentication weaknesses. First, loose equality is timing-unsafe: PHP's `==` comparison may return early if byte sequences differ, allowing an attacker to measure response time and infer whether characters in the stored password are correct. Second, the pattern compares plaintext directly, implying the stored password is also plaintext, which is both unnecessary and unsafe.

The fix uses `password_verify($password, $hash)` instead, which performs timing-safe comparison via constant-time hash verification. The stored password column must contain a bcrypt, Argon2, or password_default hash (typically via `password_hash($password, PASSWORD_DEFAULT)`), not plaintext. When the user row is not found, the code verifies the submitted password against a `DUMMY_HASH` constant (generated once with `password_hash()` at the same cost as production hashes) to ensure the verification step takes the same time whether the account exists or not. This prevents user-enumeration attacks based on response-time measurement.

The `session_regenerate_id(true)` call is already present and correct: it invalidates any session ID planted by an attacker before login, ensuring the authenticated session is bound to a fresh, server-generated identifier.

## Behaviour changes

- `password_verify()` replaces `==` comparison. Returns a boolean (true/false) with timing-safe verification.
- `DUMMY_HASH` constant must be added at class scope, generated once with `password_hash('', PASSWORD_DEFAULT)` or `password_hash('dummy', PASSWORD_DEFAULT)` at initialization. This preserves the lookup-miss timing channel prevention specified in the CWE-287 guidance.
- The check now requires that the stored `password` column contains a hash (not plaintext). If the legacy database stores plaintext, migrate passwords to hashes via `password_hash($plaintext, PASSWORD_DEFAULT)` and update the schema before deploying this fix.
- Successful login flow is unchanged: session is regenerated and user context populated as before.
- Failed login (wrong password or missing user) returns the same generic error message, which is correct—do not distinguish between the two cases in the response.
- If `password_needs_rehash($user['password'], PASSWORD_DEFAULT)` is true (hash is outdated), rehash and store it immediately after successful verification: `$user['password'] = password_hash($password, PASSWORD_DEFAULT); $stmt = $this->db->prepare('UPDATE users SET password = :hash WHERE id = :id'); $stmt->execute(['hash' => $user['password'], 'id' => $user['id']]);`
