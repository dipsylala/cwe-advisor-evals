## Verdict

**Confirmed.** The code directly compares plaintext passwords using string equality (`==`), which is vulnerable to timing attacks and lacks secure cryptographic verification.

## Source

```go
if req.Password == user.Password {
    http.SetCookie(w, &http.Cookie{
        Name:     "session",
        Value:    user.Username,
        HttpOnly: true,
        Secure:   true,
    })
    w.WriteHeader(http.StatusOK)
    return
}
```

## Fix

Import the `crypto/subtle` package and use `ConstantTimeCompare()` for the password verification:

```go
import (
    "crypto/subtle"
    "encoding/json"
    "net/http"
)

// In LoginHandler:
if subtle.ConstantTimeCompare([]byte(req.Password), []byte(user.Password)) == 1 {
    http.SetCookie(w, &http.Cookie{
        Name:     "session",
        Value:    user.Username,
        HttpOnly: true,
        Secure:   true,
    })
    w.WriteHeader(http.StatusOK)
    return
}
```

## Explanation

The original code uses direct string equality (`==`), which returns immediately upon finding the first differing byte. An attacker can measure response times to infer when they've guessed a prefix of the password correctly, enabling a timing-based attack to progressively narrow the password space.

`crypto/subtle.ConstantTimeCompare()` performs byte-by-byte comparison in constant time regardless of where differences occur, eliminating the timing side-channel. It returns 1 on match, 0 on mismatch.

This addresses the core authentication weakness by ensuring password comparison cannot leak information through timing, bringing the code into compliance with secure authentication practices.
