## Verdict

Exploitable. The `lockoutOnFailure: false` parameter disables account lockout, allowing unlimited brute force password guessing attempts. Additionally, using the `string userName` overload bypasses timing-attack mitigation during user lookup.

## Source

User-supplied login credentials from the LoginViewModel form:
- `model.UserName` - the account name being authenticated
- `model.Password` - the password being verified
- `model.RememberMe` - the remember-me preference

## Fix

**Vulnerable code:**
```csharp
// Line 27: lockoutOnFailure: false disables account lockout
var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, lockoutOnFailure: false);

if (result.Succeeded)
{
    return RedirectToAction("Index", "Home");
}

ModelState.AddModelError(string.Empty, "Invalid login attempt.");
return View(model);
```

**Fixed code:**
```csharp
// Resolve the user first to avoid timing attacks that reveal account existence
var user = await _signInManager.UserManager.FindByNameAsync(model.UserName);

SignInResult result;
if (user != null)
{
    // Use the TUser overload with lockoutOnFailure: true to enable account lockout
    result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);
}
else
{
    // Hash a decoy credential to keep response time consistent, preventing user enumeration via timing
    var dummyHash = await _signInManager.UserManager.PasswordHasher.HashPasswordAsync(new IdentityUser(), "dummy");
    await Task.Run(() => _signInManager.UserManager.PasswordHasher.VerifyHashedPassword(new IdentityUser(), dummyHash, model.Password));
    result = SignInResult.Failed;
}

if (result.IsLockedOut)
{
    ModelState.AddModelError(string.Empty, "Account is locked due to multiple failed login attempts. Please try again later.");
    return View(model);
}

if (result.Succeeded)
{
    return RedirectToAction("Index", "Home");
}

ModelState.AddModelError(string.Empty, "Invalid login attempt.");
return View(model);
```

## Explanation

The fix enables account lockout by setting `lockoutOnFailure: true`, which enforces the lockout policy configured via `IdentityOptions.Lockout` (typically 5 failed attempts triggering a 15-minute lockout). This prevents brute force password guessing. Additionally, the fix resolves the user account first using `UserManager.FindByNameAsync`, then uses the `TUser` overload of `PasswordSignInAsync` instead of the `string userName` overload. When the user is not found, the code hashes a decoy credential using the application's configured hasher to ensure response time is consistent regardless of whether the account exists, preventing timing-based user enumeration attacks. The code also now properly branches on `result.IsLockedOut` to provide appropriate feedback when an account is locked.

## Behaviour changes

- **Added user resolution**: The code now explicitly calls `FindByNameAsync` before attempting authentication. This ensures the `TUser` overload is used, which is the recommended pattern and enables consistent timing for unknown accounts.
- **Added lockout handling**: The code now checks `result.IsLockedOut` and returns an appropriate error message. Previously, locked accounts were treated identically to failed authentication.
- **Added decoy hash verification**: When a user is not found, the code verifies a decoy password against a decoy hash (created at the start of the branch) to match the CPU cost of actual password verification. This prevents attackers from discerning account existence based on response timing.
- **Simplified error handling**: The generic "Invalid login attempt" message now applies uniformly to both missing accounts and wrong passwords, further preventing user enumeration.
- **Return contract preserved**: The method still returns a View on invalid credentials and redirects on success, maintaining backward compatibility with the form-based authentication flow.
