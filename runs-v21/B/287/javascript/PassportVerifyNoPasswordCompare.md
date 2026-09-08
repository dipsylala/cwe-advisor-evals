# CWE-287: Improper Authentication

## Verdict

**Exploitable.** The verify callback at line 19 calls `done(null, user)` after a successful username lookup without comparing the supplied password against any stored hash. Authentication succeeds for any known username, regardless of password.

## Source

Vulnerable code location: `auth.js` line 19, within the LocalStrategy verify callback.

Data flow:
1. `username` and `password` come from the login request body
2. `User.findOne({ username })` queries for the user record
3. If found, the callback calls `done(null, user)` directly without verifying the password
4. Passport accepts the user as authenticated without ever comparing credentials

The vulnerability allows bypass of password verification entirely.

## Fix

### File: auth.js

```javascript
// Passport.js local authentication strategy for the /login route.
// passport@0.7.0, passport-local@1.0.0
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const User = require("../models/User");

// A genuine bcrypt hash at cost 10 (the default), used for unknown users to prevent timing-based enumeration.
const DUMMY_HASH = "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36DRcT/6";

passport.use(
  new LocalStrategy(
    { usernameField: "username", passwordField: "password" },
    async (username, password, done) => {
      try {
        const user = await User.findOne({ username });

        // Compare password against stored hash or dummy hash if user not found, preventing timing-based user enumeration.
        const passwordHash = user?.passwordHash ?? DUMMY_HASH;
        const passwordMatch = await bcrypt.compare(password, passwordHash);

        if (!passwordMatch) {
          return done(null, false, { message: "Invalid credentials" });
        }

        if (!user) {
          return done(null, false, { message: "Unknown username" });
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

The fix adds password verification before accepting any user as authenticated:

1. **Import bcrypt**: Added `const bcrypt = require("bcrypt")` to enable hash comparison.

2. **Define DUMMY_HASH**: A genuine bcrypt hash (at cost factor 10, the default) is used for unknown users. When the user lookup misses, the code compares the supplied password against this dummy instead of returning early. This prevents timing-based user enumeration—an attacker cannot determine whether a username exists by measuring response time.

3. **Add password comparison**: Before accepting the user, the callback now:
   - Extracts the stored password hash with `user?.passwordHash ?? DUMMY_HASH` (or uses the dummy if the user doesn't exist or has no hash)
   - Calls `bcrypt.compare(password, passwordHash)` to verify the supplied password against the hash
   - Returns `done(null, false)` if the password does not match (guarding against both wrong passwords and unknown usernames)
   - Only proceeds to `done(null, user)` if both the password matches and the user was actually found

4. **Preserve structure**: The fix maintains the existing error handling in the catch block and keeps session serialization unchanged. It directly addresses the authentication bypass without introducing other changes.

The fix ensures that accessing a protected resource requires knowledge of both a valid username *and* its corresponding password—the foundational security property of password-based authentication.

## Behaviour changes

- **Authentication now requires both username and password**: Previously, knowing a valid username was sufficient to authenticate. Now an attacker must also supply the correct password.
- **All login failures return `401`**: Both wrong-password and unknown-username cases now return `done(null, false)` with a generic "Invalid credentials" message, preventing user enumeration.
- **No change to session management**: Session serialization and deserialization logic remain unchanged. Passport 0.7.0+ regenerates the session automatically during login.
- **Dependency addition**: The `bcrypt` package is now required. It must be listed in `package.json` (commonly as `"bcrypt": "^5.0.0"` or newer).
- **Timing**: Each login attempt now runs `bcrypt.compare()` regardless of whether the user exists, taking approximately 100–300ms. This is the intended cost of bcrypt; the delay is uniform across both branches to prevent timing leaks.
