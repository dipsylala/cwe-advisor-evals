using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace ContosoPortal.Profile
{
    public class GreetingService
    {
        private readonly WelcomeBannerRenderer _renderer;

        public GreetingService(WelcomeBannerRenderer renderer)
        {
            _renderer = renderer;
        }

        public async Task BuildAndRenderBanner(GreetingRequest request, HttpResponse response)
        {
            string trimmedNickname = request.Nickname.Trim();
            if (trimmedNickname.Length > 60)
            {
                trimmedNickname = trimmedNickname.Substring(0, 60);
            }

            var banner = new BannerContent(trimmedNickname, request.RequestedAt);
            await _renderer.Write(response, banner);
        }
    }

    public class BannerContent
    {
        public string Message { get; }
        public DateTime RequestedAt { get; }

        public BannerContent(string message, DateTime requestedAt)
        {
            Message = message;
            RequestedAt = requestedAt;
        }
    }
}
