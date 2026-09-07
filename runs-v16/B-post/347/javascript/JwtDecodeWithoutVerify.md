## Verdict

Exploitable. The code uses `jwt.decode()` to extract claims from a user-supplied bearer token without verifying the signature. An attacker can forge any JWT token with arbitrary claims (e.g., `"role": "admin"`) and the authorization check on line 18 will accept it, bypassing authentication.

## Source

Line 8: `const authHeader = req.headers['authorization'] || '';` - The Authorization header is attacker-controlled.

## Fix

**Vulnerable code (line 16):**
```javascript
const claims = jwt.decode(token);
```

**Fixed code:**
```javascript
let claims;
try {
  claims = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
} catch (err) {
  return res.status(401).send('Invalid token');
}
```

Or, if using an RSA public key for RS256 tokens:
```javascript
let claims;
try {
  claims = jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ['RS256'] });
} catch (err) {
  return res.status(401).send('Invalid token');
}
```

## Explanation

The vulnerability is that `jwt.decode()` extracts the token payload without checking the signature at all. It will accept any forged token. The fix replaces it with `jwt.verify()`, which validates the cryptographic signature using a secret key (for HMAC algorithms like HS256) or a public key (for asymmetric algorithms like RS256). The explicit `algorithms` array restricts the accepted signature algorithm to the one you expect, preventing algorithm confusion attacks. Error handling is added to reject tokens that fail verification (malformed, expired, tampered, or signed with a different key). The verification key must come from a trusted location such as environment variables or a secure keystore, never from the token itself.

## Behaviour changes

1. **Verification is now mandatory**: The original code silently accepted any JWT regardless of its signature. The fixed code rejects any token that does not verify successfully.

2. **Error handling added**: The fixed code wraps the verification in a try-catch block and returns a 401 response if verification fails. The original code did not have this error path.

3. **Requires a secret/public key**: The fix requires `JWT_SECRET` or `JWT_PUBLIC_KEY` to be available in environment variables. The original code had no such dependency. This must be configured before deployment.

4. **Reduced attack surface**: By specifying `algorithms: ['HS256']` (or your chosen algorithm), the code prevents attackers from changing the algorithm header to "none" or switching between signing methods, which are known bypass techniques.

5. **Token expiration and standard claims**: Once `jwt.verify()` is in place, add additional checks using options like `{ issuer, audience, expiresIn }` to harden further - `jwt.verify()` will automatically validate these if present in the token.
