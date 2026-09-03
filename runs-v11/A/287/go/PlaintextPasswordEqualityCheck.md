## Verdict
The direct string comparison of plaintext passwords at line 47 fails to apply cryptographic authentication. Passwords must be verified using a one-way hashing algorithm with timing-attack resistance to prevent credential exposure if the database is compromised and to defend against timing analysis.

## Source
Line 47:
```go
if req.Password == user.Password {
```

The comparison uses the `==` operator to check string equality between the submitted password (`req.Password`) and the stored password (`user.Password`), both in plaintext. This violates CWE-287 by storing and comparing passwords without cryptographic protection.

## Fix
Apply a cryptographic password hashing and verification approach:

1. **At signup or password reset:** hash the password using `golang.org/x/crypto/bcrypt` with `bcrypt.GenerateFromPassword()`, storing the resulting hash in the user store instead of the plaintext password.

2. **At authentication (line 47):** replace the equality check with `bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))`.

The corrected code structure:
```go
err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
if err == nil {
    // password matches; issue session cookie
    http.SetCookie(w, &http.Cookie{...})
} else {
    http.Error(w, "invalid username or password", http.StatusUnauthorized)
}
```

Update the User struct's `Password` field to hold a bcrypt hash (a string of ~60 characters), not plaintext.

## Explanation
CWE-287 arises when passwords stored in plaintext can be read if the storage is compromised. Bcrypt applies a one-way hash function with built-in salting and cost parameters, making the hash computationally difficult to reverse. The `bcrypt.CompareHashAndPassword()` function compares the submitted password against the stored hash and is inherently resistant to timing attacks because it runs in constant time regardless of whether the hash is valid.

Direct string comparison (`==`) exposes the full plaintext password in memory and offers no protection if the database leaks; it also allows timing-based attacks on the password check if the comparison exits early on mismatch. Bcrypt remedies both: it verifies the password without exposing plaintext and provides constant-time comparison.
