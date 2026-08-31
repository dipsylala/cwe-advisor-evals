using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace ContosoPortal.Profile
{
    [ApiController]
    [Route("profile")]
    public class ProfileController : ControllerBase
    {
        private readonly GreetingService _greetingService;

        public ProfileController(GreetingService greetingService)
        {
            _greetingService = greetingService;
        }

        [HttpGet("welcome")]
        public async Task Welcome()
        {
            string nickname = Request.Query["nickname"].ToString();
            if (string.IsNullOrWhiteSpace(nickname))
            {
                nickname = "Guest";
            }

            var greetingRequest = new GreetingRequest(nickname, DateTime.UtcNow);
            await _greetingService.BuildAndRenderBanner(greetingRequest, HttpContext.Response);
        }
    }

    public class GreetingRequest
    {
        public string Nickname { get; }
        public DateTime RequestedAt { get; }

        public GreetingRequest(string nickname, DateTime requestedAt)
        {
            Nickname = nickname;
            RequestedAt = requestedAt;
        }
    }
}
