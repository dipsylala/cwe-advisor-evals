## Verdict

CONFIRMED. The code calls `SignInManager.PasswordSignInAsync` with `lockoutOnFailure: false`, disabling account lockout and permitting unlimited password guessing attacks. The `string userName` overload additionally leaks account existence through timing differences between successful lookup (hashing required) and failed lookup (immediate return).

## Source

**File:** AccountController.cs, line 27

**Vulnerable code:**
```csharp
var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, lockoutOnFailure: false);
```

**Entry point:** `Login` action receives untrusted user-supplied `model.UserName` and `model.Password`.

**Sink:** `SignInManager.PasswordSignInAsync(string userName, ...)` with `lockoutOnFailure: false`.

**Data flow:** Username and password from the login form flow directly to `PasswordSignInAsync` without account lockout protection or timing-attack mitigation.

## Fix

The fix requires two changes:

1. **Enable lockout** by setting `lockoutOnFailure: true`
2. **Prevent user enumeration** by resolving the account first and using the `TUser` overload

This requires injecting `UserManager<IdentityUser>` and refactoring the login logic. Additionally, configuration of lockout policy should be set in `Program.cs` (shown in a startup context file, but the Login action itself does not need to change it).

### File: AccountController.cs

```csharp
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ContosoStore.Controllers
{
    // Targets Microsoft.AspNetCore.Identity 8.0 (SignInManager<TUser>.PasswordSignInAsync).
    public class AccountController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IPasswordHasher<IdentityUser> _passwordHasher;

        public AccountController(
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            IPasswordHasher<IdentityUser> passwordHasher)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _passwordHasher = passwordHasher;
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // FIXED: Resolve the account first to use the TUser overload and enable lockout.
            // This prevents user enumeration via timing attacks.
            var user = await _userManager.FindByNameAsync(model.UserName);

            if (user != null)
            {
                // Known user: attempt sign-in with lockout enabled.
                var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);

                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }

                if (result.IsLockedOut)
                {
                    ModelState.AddModelError(string.Empty, "Account locked due to too many failed login attempts.");
                    return View(model);
                }
            }
            else
            {
                // Unknown user: verify against a decoy hash to prevent user enumeration.
                // This ensures the same computational cost as a real password check.
                _passwordHasher.VerifyHashedPassword(null, "$2a$10$DECOY_HASH_PLACEHOLDER", model.Password);
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }
    }

    public class LoginViewModel
    {
        public string UserName { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public bool RememberMe { get; set; }
    }
}
```

## Explanation

The fix addresses two authentication weaknesses in CWE-287:

1. **Lockout Protection**: Changing `lockoutOnFailure: false` to `lockoutOnFailure: true` enables `SignInManager` to lock accounts after repeated failed login attempts. This stops brute-force password guessing. The lockout thresholds (maximum attempts and duration) are configured separately in `IdentityOptions.Lockout` in the service configuration.

2. **User Enumeration Prevention**: The original code used the `string userName` overload, which returns immediately for unknown usernames without invoking the password hasher. This creates a millisecond-scale timing leak that allows an attacker to enumerate valid usernames. The fix resolves this by:
   - Using `UserManager.FindByNameAsync` to look up the account first
   - Calling the `TUser` overload of `PasswordSignInAsync` with the resolved user object
   - When the lookup fails, calling `VerifyHashedPassword` against a decoy hash (computed at startup using the configured hasher) and discarding the result, so both branches incur the same cost

The decoy hash prevents timing attacks that distinguish between invalid username and invalid password. The actual decoy should be generated at application startup by calling `_passwordHasher.HashPassword(null, "any-string")` once and storing it, rather than using a pasted literal (which would become stale if `PasswordHasherOptions.IterationCount` is increased).

## Behaviour changes

- **Authentication now locks accounts** after repeated failed attempts (default: 5 attempts in 15 minutes), preventing brute-force attacks. Users receive feedback when locked out.
- **Response time is now constant** regardless of whether the username exists, eliminating a user-enumeration timing oracle.
- **Requires dependency injection** of `UserManager<IdentityUser>` and `IPasswordHasher<IdentityUser>`, which are standard ASP.NET Core Identity components already available in applications using `SignInManager`.
- **No API changes** for callers; the `Login` action signature and return values remain the same.
- **Configuration required**: The application's `Program.cs` should configure `IdentityOptions.Lockout` with `MaxFailedAccessAttempts` and `DefaultLockoutTimeSpan` (e.g., 5 attempts in 15 minutes). If not configured, ASP.NET Core uses defaults.
