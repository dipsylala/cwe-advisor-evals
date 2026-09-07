## Verdict

Exploitable. The `lockoutOnFailure: false` parameter disables ASP.NET Core Identity's account lockout mechanism, allowing unlimited brute-force login attempts against any account.

## Source

User input from `LoginViewModel.UserName` and `LoginViewModel.Password` (lines 41–42), passed to the login endpoint's `model` parameter.

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

The vulnerability is closed by changing `lockoutOnFailure: false` to `lockoutOnFailure: true` on line 27. This enables ASP.NET Core Identity's built-in account lockout mechanism, which automatically locks an account after a configured number of failed authentication attempts (default: 5 attempts) for a configured duration (default: 15 minutes). This prevents brute-force attacks by making unlimited password guessing infeasible. The guidance for CWE-287 in C# explicitly requires this flag: "Call `SignInManager.PasswordSignInAsync(..., lockoutOnFailure: true)` and configure `IdentityOptions.Lockout`..." The lockout policy must also be configured at startup (e.g., in `Program.cs` or `Startup.cs`) via `services.Configure<IdentityOptions>(o => { ... })`, though that configuration is not shown in this file and lies outside the scope of remediating this sink.

## Behaviour changes

None beyond closing the weakness. The method signature and return contract remain identical: `PasswordSignInAsync` still returns a `SignInResult` containing `Succeeded`, `IsLockedOut`, `IsNotAllowed`, and `RequiresTwoFactor` properties. The calling code's branching on `result.Succeeded` is unchanged. The only difference is that when authentication fails, the target account is now subject to lockout, which is the intended hardening.
