## Verdict

Confirmed. The code disables account lockout during authentication attempts, removing a critical defense against credential-guessing attacks.

## Source

Line 27 in `AccountController.cs`:

```csharp
var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, lockoutOnFailure: false);
```

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

The `lockoutOnFailure` parameter controls whether ASP.NET Core Identity temporarily locks an account after consecutive failed login attempts. Setting it to `false` disables this protection entirely, allowing attackers to perform unrestricted brute-force password guessing without triggering account lockout.

The fix changes `lockoutOnFailure: false` to `lockoutOnFailure: true`, enabling the built-in lockout mechanism. When enabled, the `SignInManager` will lock the account after a configurable number of failed attempts (controlled by the identity options' `MaxFailedAccessAttempts` setting, typically 5 by default), and the account will remain locked for a configurable duration (the `DefaultLockoutTimeSpan`, typically 5 minutes). This forces attackers to space out attempts across time or switch to other targets, making credential-guessing attacks impractical while allowing legitimate users to regain access after the lockout period expires or by confirming their email/phone.
