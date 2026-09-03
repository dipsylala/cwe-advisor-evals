## Verdict

Confirmed. The Passport.js `LocalStrategy` verify callback on line 19 calls `done(null, user)` immediately after a username lookup without comparing the supplied password against any stored hash. This authenticates any request containing a valid username, regardless of password.

## Source

**File**: `auth.js` (lines 7–25)  
**Language**: JavaScript (Passport.js 0.7.0, passport-local 1.0.0)  
**Sink**: Line 19, `return done(null, user)`

```javascript
async (username, password, done) => {
  try {
    const user = await User.findOne({ username });

    if (!user) {
      return done(null, false, { message: "Unknown username" });
    }

    // CWE-287: No password comparison before authentication
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}
```

## Fix

Add `bcrypt.compare()` to verify the supplied password against the stored hash before authenticating. Use a timing-safe dummy hash comparison when the user is not found to prevent user-enumeration timing attacks.

**Changes**:

1. Import `bcrypt` at the top of the module
2. Define a `DUMMY_HASH` constant (a valid bcrypt hash for timing-safe comparison)
3. In the verify callback, use the nullish coalescing operator (`??`) to select either the user's stored hash or the dummy hash
4. Call `bcrypt.compare(password, hashToCompare)` and authenticate only if both the user exists **and** the password matches
5. Return a generic rejection message to avoid leaking which field was incorrect

**Fixed code**:

```javascript
// Passport.js local authentication strategy for the /login route.
// passport@0.7.0, passport-local@1.0.0
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const User = require("../models/User");

// A valid bcrypt hash for timing-safe dummy comparison when user not found.
// Use a real hash (not an empty string or placeholder) at the same cost as production hashes.
const DUMMY_HASH = "$2b$10$R9h7cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ee8W8J6aE6hNhgCW";

passport.use(
  new LocalStrategy(
    { usernameField: "username", passwordField: "password" },
    async (username, password, done) => {
      try {
        const user = await User.findOne({ username });

        // Compare password against stored hash (or dummy hash if user not found)
        // to prevent timing-based user enumeration
        const hashToCompare = user?.passwordHash ?? DUMMY_HASH;
        const isMatch = await bcrypt.compare(password, hashToCompare);

        if (!user || !isMatch) {
          return done(null, false, { message: "Invalid username or password" });
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

module.exports = passport;
```

## Explanation

The vulnerability exists because the verify callback only checks if a username exists and then immediately authenticates it, bypassing password validation entirely. An attacker who knows any valid username can log in without supplying a correct password.

The fix adds mandatory password verification: `bcrypt.compare()` hashes the supplied password and compares it to the stored hash. Authentication succeeds only if both the user exists **and** the password matches.

The use of a `DUMMY_HASH` for unknown usernames is critical: it ensures that both the "user not found" and "password mismatch" branches pay the same bcrypt cost (typically 200+ milliseconds). Without this, an attacker can measure response time to determine whether a username exists in the system (user enumeration). The guidance specifies that `DUMMY_HASH` must be a genuine bcrypt hash at the same computational cost as production hashes—an empty string or placeholder hash is too fast and leaves the timing oracle open.

The error message "Invalid username or password" is intentionally generic so that a login rejection cannot be used to confirm or deny the existence of a specific username.

## Behaviour changes

- **Correct authentication**: Logins now require both a valid username and a correct password; previously, a valid username alone was sufficient.
- **Response time**: All login failures (unknown username or wrong password) now incur the same bcrypt cost and take approximately the same time, eliminating a user-enumeration timing oracle.
- **Dependencies**: The fix introduces `bcrypt` as a new runtime dependency (must be added to `package.json`). Ensure `bcrypt` 3.0 or later is installed to avoid known vulnerabilities.
- **Error message**: The rejection message changed from "Unknown username" to "Invalid username or password" to prevent username disclosure.
