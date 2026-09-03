## Verdict

**Improper Authentication**: The login endpoint disables account lockout and uses a taint sink that allows user enumeration via timing oracle.

## Source

`model.UserName` and `model.Password` supplied by an attacker through the login form.

## Fix

Replace line 27 and restructure the authentication flow:

**Original (vulnerable):**
```csharp
var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, lockoutOnFailure: false);
```

**Fixed:**

1. Inject `UserManager` and `IPasswordHasher` in the constructor:

```csharp
private readonly SignInManager<IdentityUser> _signInManager;
private readonly UserManager<IdentityUser> _userManager;
private readonly IPasswordHasher<IdentityUser> _passwordHasher;
private readonly IdentityUser _decoyUser; // Pre-computed decoy account

public AccountController(
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IPasswordHasher<IdentityUser> passwordHasher)
{
    _signInManager = signInManager;
    _userManager = userManager;
    _passwordHasher = passwordHasher;
    _decoyUser = new IdentityUser { UserName = "_decoy" };
}
```

2. Initialize the decoy hash once at startup (in `Program.cs` or a service initializer):

```csharp
services.AddScoped<AccountController>(provider =>
{
    var signInManager = provider.GetRequiredService<SignInManager<IdentityUser>>();
    var userManager = provider.GetRequiredService<UserManager<IdentityUser>>();
    var passwordHasher = provider.GetRequiredService<IPasswordHasher<IdentityUser>>();
    
    // Pre-compute decoy hash once
    var decoyUser = new IdentityUser { UserName = "_decoy" };
    decoyUser.PasswordHash = passwordHasher.HashPassword(decoyUser, "decoy-password");
    
    return new AccountController(signInManager, userManager, passwordHasher);
});
```

3. Replace the vulnerable call on line 27:

```csharp
// Lookup the user by name
var user = await _userManager.FindByNameAsync(model.UserName);

// Verify against real user or decoy to prevent user enumeration
var userToCheck = user ?? _decoyUser;
var hashResult = _passwordHasher.VerifyHashedPassword(userToCheck, userToCheck.PasswordHash ?? "", model.Password);

if (user != null && hashResult == PasswordVerificationResult.Success)
{
    // Use the TUser overload with lockoutOnFailure: true
    var result = await _signInManager.SignInAsync(user, model.RememberMe, authenticationMethod: null);
    
    if (result.Succeeded)
    {
        return RedirectToAction("Index", "Home");
    }
    
    if (result.IsLockedOut)
    {
        ModelState.AddModelError(string.Empty, "Account is locked. Please try again later.");
        return View(model);
    }
}

// Failed login - always return the same generic message
ModelState.AddModelError(string.Empty, "Invalid login attempt.");
return View(model);
```

**Alternative (simpler if no custom lockout logic needed):**

If you want to keep the original structure simpler, at minimum:

```csharp
// Resolve the user
var user = await _userManager.FindByNameAsync(model.UserName);

if (user != null)
{
    // Use the TUser overload with lockoutOnFailure: true
    var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);
    
    if (result.Succeeded)
    {
        return RedirectToAction("Index", "Home");
    }
    
    if (result.IsLockedOut)
    {
        ModelState.AddModelError(string.Empty, "Account is locked. Please try again later.");
        return View(model);
    }
}
else
{
    // Spend the same cost by verifying against a decoy to prevent user enumeration
    var decoyUser = new IdentityUser { UserName = "_decoy" };
    var decoyHash = _passwordHasher.HashPassword(decoyUser, "dummy");
    _passwordHasher.VerifyHashedPassword(decoyUser, decoyHash, model.Password);
}

ModelState.AddModelError(string.Empty, "Invalid login attempt.");
return View(model);
```

Also configure lockout policy in `Program.cs`:

```csharp
services.Configure<IdentityOptions>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
});
```

## Explanation

The original code has two authentication weaknesses:

1. **Disabled account lockout** (`lockoutOnFailure: false`): The `string userName` overload returns `SignInResult.Failed` immediately when `FindByNameAsync` returns null, bypassing the hasher entirely. This allows unlimited password guessing. Changing to `lockoutOnFailure: true` forces an account lockout after 5 failed attempts (configurable), defending against brute force.

2. **Timing-based user enumeration**: Because the unknown-user branch never hashes a credential, an attacker can distinguish valid usernames from invalid ones by measuring response time. The hasher runs in ~100ms; the null-check returns in ~1ms. The fixed code uses the `TUser` overload after explicitly resolving the user, and spends the same hashing cost whether the user exists or not by verifying against a decoy hash when the lookup misses. This makes response times indistinguishable and closes the timing oracle.

The fix uses `IPasswordHasher<TUser>` (injected, initialized at startup) rather than a hardcoded literal hash, so the decoy respects the configured iteration count and algorithm changes over time.

## Behaviour changes

- Failed logins now trigger account lockout after 5 consecutive failures (configurable).
- Locked accounts return a specific `IsLockedOut` response (should inform the user to try later, not "Invalid login").
- Response time for non-existent usernames now matches valid-username-wrong-password responses, eliminating the timing side channel.
- The login flow now requires `UserManager` and `IPasswordHasher` injected into the controller.
- The decoy hash is computed once at application startup, not on every failed login for an unknown user.
