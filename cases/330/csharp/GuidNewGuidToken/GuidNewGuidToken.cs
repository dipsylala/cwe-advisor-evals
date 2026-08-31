using System;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PasswordResetController : ControllerBase
    {
        private static readonly ConcurrentDictionary<string, string> ResetTokens = new();

        [HttpPost("request")]
        public IActionResult RequestReset([FromForm] string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return BadRequest("Email is required");
            }

            // SAST FINDING: CWE-330 (Use of Insufficiently Random Values) reported here. Sink is the next statement.
            string resetToken = Guid.NewGuid().ToString();

            ResetTokens[resetToken] = email;

            return Ok(new { token = resetToken });
        }
    }
}
