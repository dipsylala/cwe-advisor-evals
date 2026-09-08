## Verdict
CWE-287 (Improper Authentication) confirmed. The authentication strategy fetches the user but authenticates without comparing the provided password to the stored hashed password.

## Source
The vulnerability is in the LocalStrategy verify callback at line 19. After confirming a user exists, the code immediately calls `done(null, user)` without ever validating the supplied password against the user's stored hashed password in the database.

## Fix
### File: auth.js
```javascript
// Passport.js local authentication strategy for the /login route.
// passport@0.7.0, passport-local@1.0.0
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const User = require("../models/User");
const bcrypt = require("bcrypt");

passport.use(
  new LocalStrategy(
    { usernameField: "username", passwordField: "password" },
    async (username, password, done) => {
      try {
        const user = await User.findOne({ username });

        if (!user) {
          return done(null, false, { message: "Unknown username" });
        }

        // Compare the provided password with the stored hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);

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
The fix adds password verification before authentication succeeds:

1. Import `bcrypt` to safely compare passwords.
2. After confirming the user exists, call `bcrypt.compare(password, user.password)` to verify the supplied password matches the stored hashed password.
3. If the comparison fails, return `done(null, false)` with an authentication error message, rejecting the login attempt.
4. Only if the password is valid does the code call `done(null, user)` to authenticate.

This ensures that successful authentication requires both a valid username and a correct password, closing the improper authentication vulnerability.
