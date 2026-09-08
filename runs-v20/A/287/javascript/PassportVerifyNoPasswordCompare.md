## Verdict
Confirmed. The Passport `LocalStrategy` verify callback looks up the user by username and then calls `done(null, user)` unconditionally - it never checks the submitted `password` against any credential stored on the account. Any request that supplies a valid username (with any password value, including an empty or arbitrary string) is authenticated as that user, because authentication success depends solely on the account existing.

## Source
`password` - the `passwordField: "password"` value passed into the `LocalStrategy` verify callback at `auth.js:10`, sourced from the login request body by `passport-local`.

## Fix
The fix adds a `bcrypt.compare()` check between the user lookup and the `done(null, user)` success call, so the callback only succeeds when the submitted password matches the stored hash. It also normalizes the "no such user" and "wrong password" failure paths to the same generic message, and returns a generic account-state error if a user record has no password hash set (e.g. an SSO-only account), rather than treating it as a successful login or leaking which condition failed.

### File: auth.js
```javascript
// Passport.js local authentication strategy for the /login route.
// passport@0.7.0, passport-local@1.0.0
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const User = require("../models/User");

passport.use(
  new LocalStrategy(
    { usernameField: "username", passwordField: "password" },
    async (username, password, done) => {
      try {
        const user = await User.findOne({ username });

        if (!user) {
          return done(null, false, { message: "Incorrect username or password" });
        }

        if (!user.password) {
          return done(null, false, { message: "Incorrect username or password" });
        }

        const passwordMatches = await bcrypt.compare(password, user.password);

        if (!passwordMatches) {
          return done(null, false, { message: "Incorrect username or password" });
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
`passport-local`'s contract is that the verify callback itself is responsible for validating the credential - the strategy only extracts `username`/`password` from the request and hands them to the callback. The original code performed the lookup half of authentication (does this username exist) but never the credential half (does this caller know the account's password), so `done(null, user)` was reached for every existing username regardless of what password was submitted, and Passport treats that call as a successful login (`req.login()` then establishes the session).

The fix stores/compares against a bcrypt hash rather than a plaintext or reversibly-encoded value, using `bcrypt.compare()` so the check runs in constant time relative to the hash rather than a naive string equality that could leak timing information. Both failure branches - unknown username and wrong password - return the same generic message so the response does not let a caller enumerate valid usernames by observing different error text. The `!user.password` guard treats an account with no hash on record as a failed login rather than either crashing `bcrypt.compare()` on a `null`/`undefined` hash or, worse, falling through to success.

This assumes the `User` model persists a bcrypt hash in a `password` field (consistent with `bcrypt`'s standard usage); if the schema instead stores the hash under a different field name or a different algorithm, adjust the field reference and comparison call accordingly, and confirm the `bcrypt` dependency (or an equivalent maintained hashing library) is present in the project's manifest.
