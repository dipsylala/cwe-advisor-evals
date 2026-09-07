## Verdict

Exploitable

## Source

The `password` parameter supplied in the HTTP request body, parsed by Passport's LocalStrategy from the login form.

## Fix

### Vulnerable code

```javascript
async (username, password, done) => {
  try {
    const user = await User.findOne({ username });

    if (!user) {
      return done(null, false, { message: "Unknown username" });
    }

    // SAST FINDING: CWE-287. Authenticates without comparing password.
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}
```

### Fixed code

```javascript
async (username, password, done) => {
  try {
    const user = await User.findOne({ username });

    // Compare password against stored hash; use DUMMY_HASH if user not found.
    // Prevents timing attacks that reveal whether username exists.
    const passwordHash = user?.passwordHash ?? DUMMY_HASH;
    const isPasswordValid = await bcrypt.compare(password, passwordHash);

    if (!user || !isPasswordValid) {
      return done(null, false, { message: "Invalid credentials" });
    }

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}
```

At module level, add bcrypt import and define the dummy hash:

```javascript
const bcrypt = require("bcrypt");

// Pre-computed bcrypt hash for timing attack prevention when user not found.
// Should be a valid bcrypt hash at the same cost rounds (10) as your password hashes.
// Example: Generate once with bcrypt.hash('', 10) and copy the result here.
const DUMMY_HASH = "$2b$10$weaksalt0000000000000000wgyiB/c4uO5sQP/GsAQb/kGjGBbO";
```

## Explanation

The original code authenticates any username that exists in the database without verifying the password hash. By calling `done(null, user)` immediately after finding a matching username record, the verify callback grants access to anyone who knows or guesses a valid username, regardless of whether they supply the correct password.

The fix adds password verification using bcrypt.compare() between the supplied password and the stored hash. To prevent timing attacks that leak username existence (an unknown user returns instantly; a known user takes longer for bcrypt to reject), the code compares against a dummy hash when the lookup misses, so both branches consume bcrypt's comparison time. The updated error message "Invalid credentials" covers both cases and does not distinguish between a non-existent user and an incorrect password, further preventing user enumeration.

## Behaviour changes

- **Added bcrypt dependency**: Required to securely compare password hashes. Must add `"bcrypt"` to package.json dependencies and `require("bcrypt")` at module load. The `bcrypt.compare()` call is async and returns a boolean Promise; this is properly awaited.
- **DUMMY_HASH module constant**: Added a pre-computed bcrypt hash to prevent timing attacks when the username is not found. Comparing against this hash keeps both the "user exists" and "user missing" branches at equal bcrypt cost, so network timing cannot answer whether a username exists.
- **Error message unification**: Changed from "Unknown username" (line 15) to "Invalid credentials" (both cases). This is a security improvement: the original message leaked whether the username was valid. The new message does not distinguish between user-not-found and wrong-password cases.
- **Return value unchanged**: Both original and fixed code call `done(null, false)` on failure and `done(null, user)` on success. The fixed code calls `done(null, user)` only after the password has been verified, so the return value semantics are preserved: `done(null, user)` now means "user was found AND password was correct."

