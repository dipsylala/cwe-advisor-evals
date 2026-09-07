## Verdict

CWE-287 (Improper Authentication) confirmed. The authentication strategy accepts any user matching the username without verifying the password, allowing login with any password or none.

## Source

```javascript
// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
return done(null, user);
```

Line 19 authenticates the user based solely on username existence, bypassing credential verification.

## Fix

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
          return done(null, false, { message: "Unknown username" });
        }

        // Compare provided password against stored hash
        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

        if (!isPasswordValid) {
          return done(null, false, { message: "Invalid password" });
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

The vulnerability occurs because the authentication strategy locates a user by username but never validates the password. The `done(null, user)` call on line 19 authenticates the user unconditionally, permitting login without password verification.

The fix adds a password comparison step using `bcrypt.compare()`, which safely compares the plaintext password supplied at login against the stored hash. Only if both match does the strategy proceed to authentication. If the password does not match, the strategy returns an authentication failure with `done(null, false)` instead.

This assumes the User model stores the hashed password in a field named `passwordHash`. Substitute the actual field name if different. The bcrypt library is the industry standard for password hashing in Node.js and is commonly used alongside Passport.
