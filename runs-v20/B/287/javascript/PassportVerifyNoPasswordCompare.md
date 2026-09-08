## Verdict

Exploitable. CWE-287 (Improper Authentication), confidence: high.

## Source

`username` and `password`, the credentials submitted in the Passport `local` strategy's login request body (`usernameField: "username"`, `passwordField: "password"`), reach the verify callback at `auth.js:10`.

## Fix

Location: `auth.js:19`, the `passport.use(new LocalStrategy(...))` verify callback. `User.findOne({ username })` (line 12) looks the user up, but the code never compares the submitted `password` against any stored credential before calling `done(null, user)` (line 19) - it authenticates anyone who supplies a `username` that exists, with any password. There is no validation or gate between the source and the sink that would break this path.

Sink contract before the fix: `done(null, user)` returns the found user to Passport, which serializes it into the session - the caller (Passport core) treats this as "authentication succeeded." On a missing user, `done(null, false, { message: "Unknown username" })` short-circuits before any hashing occurs, so an unknown username fails fast while a known username with any password succeeds after the same DB lookup. `catch` routes DB errors to `done(err)`. No password field is referenced anywhere in the file, and no hashing library is imported.

### File: auth.js
```javascript
// Passport.js local authentication strategy for the /login route.
// passport@0.7.0, passport-local@1.0.0
const bcrypt = require("bcrypt");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const User = require("../models/User");

// Bcrypt hash of a fixed placeholder value, generated at the same cost (10)
// used for real password hashes. Compared against on every login attempt so
// an unknown username or a passwordless (SSO-only) account pays the same
// bcrypt cost as a real check, instead of returning before hashing runs.
const DUMMY_HASH = "$2b$10$BWlvAgsNMa7c0X6AKLbDveq0mh8/zefdvw0trymd4DoIZ2Y/cG/oe";

passport.use(
  new LocalStrategy(
    { usernameField: "username", passwordField: "password" },
    async (username, password, done) => {
      try {
        const user = await User.findOne({ username });

        const passwordMatches = await bcrypt.compare(
          password,
          user?.passwordHash ?? DUMMY_HASH
        );

        if (!user || !passwordMatches) {
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

The fix adds a `bcrypt.compare()` call between the lookup and the `done()` sink, and runs it unconditionally - before checking whether `user` exists - by falling back to a fixed `DUMMY_HASH` when the lookup misses or the found record has no `passwordHash` (an SSO-only account). This closes the improper-authentication finding (no credential is ever checked) while also keeping the unknown-username and wrong-password branches paying the same bcrypt cost, so timing cannot be used to enumerate valid usernames. Both the "user not found" and "password mismatch" cases now fall through to the same `done(null, false, { message: "Invalid username or password" })` call, so a rejection carries no signal about which condition caused it. `bcrypt` is the hashing library named by the loaded CWE-287 JavaScript guidance for this exact pattern; no version floor is given by that guidance (there is no known-vulnerable release being fixed here), so pin whatever version SCA/dependency-check resolves as current when adding it to `package.json`, and confirm `bcrypt` is already a project dependency or add it if not.

## Behaviour changes

- **Rejection message text changed** from `"Unknown username"` to `"Invalid username or password"`, and is now returned identically whether the user exists or the password is wrong. Reason: the original per-case message is itself a user-enumeration oracle independent of timing - equalizing bcrypt cost alone (per the guidance's dummy-hash pattern) would not close that if the message still revealed which check failed, so unifying the message is required to fully realize the guidance's anti-enumeration intent, not an unrelated change.
- **`bcrypt.compare()` now always executes**, including for a missing user or a user with no `passwordHash`, whereas the original returned immediately on a missing user without any hashing. Reason: this is the guidance's prescribed dummy-hash comparison, needed so response time is the same for an unknown username as for a known one with a wrong password.
- **New dependency**: `bcrypt` is now `require()`d. Reason: it is the hashing comparison the sink was missing; confirm it is present in `package.json` (or add it) and let SCA/dependency-check resolve the version, per the loaded guidance.
- All other behavior is unchanged: `done(err)` on a DB error, `serializeUser`/`deserializeUser`, and the strategy's field names are untouched.

**Verification**: `node --check` on the fixed file, copied to a scratch location outside the repository - passed with no diagnostics. Additionally ran the verify callback's core logic (lookup + `bcrypt.compare` branching, with `passport`/`passport-local` mocked out) against a real `bcrypt` install in a scratch directory: a correct password authenticated; a wrong password, an unknown username, and a user record with no `passwordHash` all rejected uniformly with the same message and no thrown error; 20-sample average latency for a wrong password (58.43ms) and an unknown username (58.22ms) matched within noise, confirming the dummy-hash comparison equalizes timing as intended.

**Assumptions**: The `User` model's stored password-hash field is assumed to be named `passwordHash` (not present in the finding's file; this name is taken directly from the loaded CWE-287 JavaScript guidance's own example, `user?.passwordHash ?? DUMMY_HASH`). If the actual field is named differently (e.g. `password` or `hash`), substitute that name in the `bcrypt.compare()` call. Confidence is high overall, lowered only by this one unverified field name.
