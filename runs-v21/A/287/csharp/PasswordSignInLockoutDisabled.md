## Verdict

Real vulnerability. CWE-287 improper authentication.

## Source

**File:** AccountController.cs  
**Line:** 27

```csharp
var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, lockoutOnFailure: false);
```

The `lockoutOnFailure` parameter is set to `false`, disabling the account lockout mechanism after failed authentication attempts.

## Fix

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

        public AccountController(SignInManager<IdentityUser> signInManager)
        {
            _signInManager = signInManager;
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
            var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                return RedirectToAction("Index", "Home");
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

The vulnerability is caused by disabling account lockout during failed authentication attempts. With `lockoutOnFailure: false`, an attacker can attempt unlimited password guesses against a user account without any defensive mechanism triggering.

The fix changes `lockoutOnFailure: false` to `lockoutOnFailure: true`, enabling ASP.NET Core Identity's built-in account lockout feature. When enabled, the `SignInManager<TUser>.PasswordSignInAsync()` method automatically locks the account after a configured number of failed login attempts (the default is 5 attempts with a 5-minute lockout duration, configurable via `IdentityOptions.Lockout`). This mitigates brute force attacks on user credentials.
