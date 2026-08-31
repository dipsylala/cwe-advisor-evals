using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PasswordResetController : ControllerBase
    {
        [HttpGet("token")]
        public IActionResult GenerateResetToken([FromQuery] int seed)
        {
            // SAST FINDING: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)) reported here. Sink is the next statement.
            var rng = new Random(seed);

            var tokenBytes = new byte[16];
            rng.NextBytes(tokenBytes);
            var resetToken = Convert.ToBase64String(tokenBytes);

            return Ok(new { token = resetToken });
        }
    }
}
