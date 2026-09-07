## Verdict

VULNERABLE. The LocalStrategy verify callback authenticates any supplied username without comparing the password against the stored hash.

## Source

The vulnerability is at line 19:
```javascript
return done(null, user);
```

The code calls `done(null, user)` directly after looking up the user by username, without ever verifying the password. This grants authentication to anyone who supplies a valid username, regardless of what password they provide.

## Fix

Replace the verify callback to perform password comparison before authenticating:

```javascript
const bcrypt = require("bcrypt");

passport.use(
  new LocalStrategy(
    { usernameField: "username", passwordField: "password" },
    async (username, password, done) => {
      try {
        const user = await User.findOne({ username });
        const storedHash = user?.passwordHash || generateDummyHash();

        const isValid = await bcrypt.compare(password, storedHash);

        if (!isValid) {
          return done(null, false, { message: "Invalid password" });
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);
```

Where `generateDummyHash()` returns a cached bcrypt hash computed at the same cost as real password hashes (e.g. a pre-computed hash of a static dummy string using the same bcrypt cost factor), preventing timing-based user enumeration attacks.

## Explanation

The vulnerability exists because the code skips the essential authentication step: comparing the supplied password against the stored password hash. The Passport verify callback in a LocalStrategy is the location where password credentials must be validated. By calling `done(null, user)` without a credential comparison, the code authenticates based only on username existence, not on possession of the correct password.

The fix uses `bcrypt.compare()` to check the supplied password against the stored hash before granting authentication. When the user is not found, the code still runs `bcrypt.compare()` against a dummy hash of matching cost to avoid timing attacks that could reveal whether a username exists. Only after the comparison succeeds does the code call `done(null, user)`.

## Behaviour changes

**Before:**
- Any request with a valid username and any password value grants authentication
- Unknown usernames and known usernames respond at different speeds, enabling user enumeration

**After:**
- Authentication requires both a valid username and the correct password
- Both unknown usernames and known usernames with wrong passwords run the same bcrypt operation, preventing timing-based user enumeration
- Invalid credentials return `401` consistently
