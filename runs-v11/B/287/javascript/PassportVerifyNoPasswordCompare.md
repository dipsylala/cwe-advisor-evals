## Verdict

Confirmed. The verify callback authenticates any supplied username without comparing the password against a stored hash, granting access to any attacker who provides a known username.

## Source

The Passport.js `LocalStrategy` verify callback (lines 10-23) receives a user-supplied `password` parameter but never validates it. The user record is fetched at line 12, and at line 19 the callback returns `done(null, user)` to authenticate that user without any password comparison.

## Fix

Add bcrypt password comparison before calling `done(null, user)`. Compare against a dummy hash when the user is not found to prevent timing attacks that leak whether a username exists:

```javascript
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const User = require("../models/User");

// A genuine bcrypt hash at default cost, used to maintain consistent timing when user is not found
const DUMMY_HASH = "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36CHqV36";

passport.use(
  new LocalStrategy(
    { usernameField: "username", passwordField: "password" },
    async (username, password, done) => {
      try {
        const user = await User.findOne({ username });

        // Compare password against stored hash (or dummy if user not found)
        // This ensures both success and failure paths take similar time
        const passwordMatch = await bcrypt.compare(
          password,
          user?.passwordHash ?? DUMMY_HASH
        );

        if (!user || !passwordMatch) {
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

The fix adds `bcrypt.compare()` to verify the supplied password against the stored `passwordHash` before accepting the authentication. The password comparison happens whether the user exists or not: when the lookup misses, it compares against a `DUMMY_HASH` constant, which ensures both branches take approximately equal time to complete. This prevents an attacker from measuring response time to determine whether a username exists in the system. The callback now returns `done(null, false)` on any mismatch or missing user, rejecting the authentication attempt, and only calls `done(null, user)` after a successful password comparison.

## Behaviour changes

- Failed authentication (wrong password or unknown username) now returns `401` with message "Invalid username or password" (replacing the previous immediate success).
- Authentication now requires both a valid username and the correct password.
- Response time for missing usernames is now similar to response time for wrong passwords (prevents user enumeration via timing attacks).
- Requires `bcrypt` package to be installed as a dependency.
- Assumes the `User` model has a `passwordHash` field storing the bcrypt-hashed password; if SSO-only accounts exist with null `passwordHash`, they will still be rejected at login (correct behaviour - they should authenticate via SSO path, not local strategy).
